﻿/*
    Copyright 2017-2020 Perfare - https://github.com/Perfare/Il2CppDumper
    Copyright 2021 Katy Coe - http://www.djkaty.com - https://github.com/djkaty

    All rights reserved.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Il2CppInspector.Reflection;
using Assembly = System.Reflection.Assembly;
using BindingFlags = System.Reflection.BindingFlags;

namespace Il2CppInspector.Outputs
{
    public static class dnlibExtensions
    {
        // Add a default parameterless constructor that calls a specified base constructor
        public static MethodDef AddDefaultConstructor(this TypeDef type, IMethod @base) {
            var ctor = new MethodDefUser(".ctor", MethodSig.CreateInstance(type.Module.CorLibTypes.Void),
                MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);

            var ctorBody = new CilBody();
            ctorBody.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            ctorBody.Instructions.Add(OpCodes.Call.ToInstruction(@base));
            ctorBody.Instructions.Add(OpCodes.Ret.ToInstruction());
            ctor.Body = ctorBody;

            type.Methods.Add(ctor);
            return ctor;
        }

        // Add custom attribute to type with named property arguments
        // 'module' is the module that owns 'type'; type.Module may still be null when this is called
        public static CustomAttribute AddAttribute(this IHasCustomAttribute def, ModuleDef module, TypeDef attrTypeDef, params (string prop, object value)[] args) {
            var attRef = module.Import(attrTypeDef);
            var attCtorRef = new MemberRefUser(attrTypeDef.Module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attRef);

            // Attribute arguments
            var attrArgs = args.Select(a =>
                new CANamedArgument(false, module.CorLibTypes.String, a.prop, new CAArgument(module.CorLibTypes.String, a.value)));

            var attr = new CustomAttribute(attCtorRef, null, attrArgs);

            def.CustomAttributes.Add(attr);
            return attr;
        }
    }

    // Output module to create .NET DLLs containing type definitions
    public class AssemblyShims
    {
        // .NET type model
        private readonly TypeModel model;

        // Our custom attributes
        private TypeDef addressAttribute;
        private TypeDef fieldOffsetAttribute;
        private TypeDef attributeAttribute;
        private TypeDef metadataOffsetAttribute;
        private TypeDef tokenAttribute;

        // The namespace for our custom types
        private const string rootNamespace = "Il2CppInspector.DLL";

        // Mapping of our type model to dnlib types
        //private Dictionary<TypeInfo, TypeDef> typeMap = new Dictionary<TypeInfo, TypeDef>();

        // All modules (single-module assemblies)
        private List<ModuleDef> modules = new List<ModuleDef>();

        public AssemblyShims(TypeModel model) => this.model = model;

        // Generate base DLL with our custom types
        private ModuleDef CreateBaseAssembly() {
            // Create DLL with our custom types
            var module = CreateAssembly("Il2CppInspector.dll");

            var attributeCtor = typeof(Attribute).GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)[0];
            var attributeTypeRef = module.Import(typeof(Attribute));
            var attributeCtorRef = module.Import(attributeCtor);

            var stringField = new FieldSig(module.CorLibTypes.String);

            // Create a type deriving from System.Attribute and add it to the assembly
            TypeDefUser createAttribute(string name) {
                var attribute = new TypeDefUser(rootNamespace, name, attributeTypeRef);
                attribute.Attributes = TypeAttributes.Public | TypeAttributes.BeforeFieldInit;
                module.Types.Add(attribute);
                return attribute;
            }

            // Create our custom attributes for compatibility with Il2CppDumper
            // TODO: New format with numeric values where applicable
            addressAttribute = createAttribute("AddressAttribute");
            addressAttribute.Fields.Add(new FieldDefUser("RVA", stringField, FieldAttributes.Public));
            addressAttribute.Fields.Add(new FieldDefUser("Offset", stringField, FieldAttributes.Public));
            addressAttribute.Fields.Add(new FieldDefUser("VA", stringField, FieldAttributes.Public));
            addressAttribute.Fields.Add(new FieldDefUser("Slot", stringField, FieldAttributes.Public));
            addressAttribute.AddDefaultConstructor(attributeCtorRef);

            fieldOffsetAttribute = createAttribute("FieldOffsetAttribute");
            fieldOffsetAttribute.Fields.Add(new FieldDefUser("Offset", stringField, FieldAttributes.Public));
            fieldOffsetAttribute.AddDefaultConstructor(attributeCtorRef);

            attributeAttribute = createAttribute("AttributeAttribute");
            attributeAttribute.Fields.Add(new FieldDefUser("Name", stringField, FieldAttributes.Public));
            attributeAttribute.Fields.Add(new FieldDefUser("RVA", stringField, FieldAttributes.Public));
            attributeAttribute.Fields.Add(new FieldDefUser("Offset", stringField, FieldAttributes.Public));
            attributeAttribute.AddDefaultConstructor(attributeCtorRef);

            metadataOffsetAttribute = createAttribute("MetadataOffsetAttribute");
            metadataOffsetAttribute.Fields.Add(new FieldDefUser("Offset", stringField, FieldAttributes.Public));
            metadataOffsetAttribute.AddDefaultConstructor(attributeCtorRef);

            tokenAttribute = createAttribute("TokenAttribute");
            tokenAttribute.Fields.Add(new FieldDefUser("Token", stringField, FieldAttributes.Public));
            tokenAttribute.AddDefaultConstructor(attributeCtorRef);

            return module;
        }

        // Create a new DLL assembly definition
        private ModuleDefUser CreateAssembly(string name) {
            // Create module
            var module = new ModuleDefUser(name) { Kind = ModuleKind.Dll };

            // Create assembly
            var ourVersion = Assembly.GetAssembly(typeof(Il2CppInspector)).GetName().Version;
            var asm = new AssemblyDefUser(name.Replace(".dll", ""), ourVersion);

            // Add module to assembly
            asm.Modules.Add(module);
            return module;
        }
 
        // Generate type recursively with all nested types
        private TypeDefUser CreateType(ModuleDef module, TypeInfo type) {
            // Initialize with base class
            var mType = new TypeDefUser(type.Namespace, type.BaseName, GetTypeRef(module, type.BaseType)) {
                Attributes = (TypeAttributes) type.Attributes
            };

            // Generic parameters
            foreach (var gp in type.GenericTypeParameters) {
                var p = new GenericParamUser((ushort) gp.GenericParameterPosition, (GenericParamAttributes) gp.GenericParameterAttributes, gp.Name);

                // Generic constraints (types and interfaces)
                foreach (var c in gp.GetGenericParameterConstraints())
                    p.GenericParamConstraints.Add(new GenericParamConstraintUser(GetTypeRef(module, c)));

                mType.GenericParameters.Add(p);
            }

            // Interfaces
            foreach (var @interface in type.ImplementedInterfaces)
                mType.Interfaces.Add(new InterfaceImplUser(GetTypeRef(module, @interface)));

            // Add nested types
            foreach (var nestedType in type.DeclaredNestedTypes)
                mType.NestedTypes.Add(CreateType(module, nestedType));

            // Add properties
            foreach (var prop in type.DeclaredProperties)
                AddProperty(module, mType, prop);

            // Add methods that aren't properties
            var props = type.DeclaredProperties.SelectMany(p => new[] { p.GetMethod, p.SetMethod }).Where(m => m != null);

            foreach (var method in type.DeclaredConstructors.AsEnumerable<MethodBase>().Concat(type.DeclaredMethods).Except(props))
                AddMethod(module, mType, method);

            // Add token attribute
            if (type.Definition != null)
                mType.AddAttribute(module, tokenAttribute, ("Token", $"0x{type.Definition.token:X8}"));

            return mType;
        }

        private PropertyDef AddProperty(ModuleDef module, TypeDef mType, PropertyInfo prop) {
            var s = PropertySig.CreateInstance(GetTypeSig(module, prop.PropertyType));

            var mProp = new PropertyDefUser(prop.Name, s, (PropertyAttributes) prop.Attributes);

            if (prop.CanRead)
                mProp.GetMethod = AddMethod(module, mType, prop.GetMethod);
            if (prop.CanWrite)
                mProp.SetMethod = AddMethod(module, mType, prop.SetMethod);

            // Add token attribute
            mProp.AddAttribute(module, tokenAttribute, ("Token", $"0x{prop.Definition.token:X8}"));

            // Add property to type
            mType.Properties.Add(mProp);
            return mProp;
        }

        private MethodDef AddMethod(ModuleDef module, TypeDef mType, MethodBase method) {
            // Return type and parameter signature
            var s = MethodSig.CreateInstance(
                    method is MethodInfo mi? GetTypeSig(module, mi.ReturnType) : module.CorLibTypes.Void,
                    method.DeclaredParameters.Select(p => GetTypeSig(module, p.ParameterType))
                    .ToArray());

            // Definition
            var mMethod = new MethodDefUser(method.Name, s, (MethodImplAttributes) method.MethodImplementationFlags, (MethodAttributes) method.Attributes);

            // Generic type parameters
            foreach (var gp in method.GetGenericArguments()) {
                var p = new GenericParamUser((ushort) gp.GenericParameterPosition, (GenericParamAttributes) gp.GenericParameterAttributes, gp.Name);

                // Generic constraints (types and interfaces)
                foreach (var c in gp.GetGenericParameterConstraints())
                    p.GenericParamConstraints.Add(new GenericParamConstraintUser(GetTypeRef(module, c)));

                mMethod.GenericParameters.Add(p);
            }

            // Parameter names and default values
            foreach (var param in method.DeclaredParameters) {
                var p = new ParamDefUser(param.Name, (ushort) (param.Position + 1));

                if (param.DefaultValueMetadataAddress != 0) {
                    if (param.HasDefaultValue)
                        p.Constant = new ConstantUser(param.DefaultValue);

                    // Add offset attribute if no default value but metadata present
                    else
                        p.AddAttribute(module, metadataOffsetAttribute, ("Offset", $"0x{param.DefaultValueMetadataAddress:X8}"));
                }
                mMethod.ParamDefs.Add(p);
            }

            // Method body
            if (method.VirtualAddress.HasValue && method.DeclaringType.BaseType?.FullName != "System.MulticastDelegate") {
                mMethod.Body = new CilBody();
                var inst = mMethod.Body.Instructions;

                // Return nothing if return type is void
                if (mMethod.ReturnType.FullName == "System.Void")
                    inst.Add(OpCodes.Ret.ToInstruction());

                // Return default for value type
                else if (mMethod.ReturnType.IsValueType) {
                    var result = new Local(mMethod.ReturnType);
                    mMethod.Body.Variables.Add(result);

                    inst.Add(OpCodes.Ldloca_S.ToInstruction(result));
                    inst.Add(OpCodes.Initobj.ToInstruction(mMethod.ReturnType.ToTypeDefOrRef()));
                    inst.Add(OpCodes.Ldloc_0.ToInstruction());
                    inst.Add(OpCodes.Ret.ToInstruction());
                }

                // Return null for reference types
                else {
                    inst.Add(OpCodes.Ldnull.ToInstruction());
                    inst.Add(OpCodes.Ret.ToInstruction());
                }
            }

            // Add token attribute
            mMethod.AddAttribute(module, tokenAttribute, ("Token", $"0x{method.Definition.token:X8}"));

            // Add method pointer attribute
            if (method.VirtualAddress.HasValue) {
                var args = new List<(string,object)> {
                        ("RVA", (method.VirtualAddress.Value.Start - model.Package.BinaryImage.GlobalOffset).ToAddressString()),
                        ("Offset", string.Format("0x{0:X}", model.Package.BinaryImage.MapVATR(method.VirtualAddress.Value.Start))),
                        ("VA", method.VirtualAddress.Value.Start.ToAddressString())
                    };
                if (method.Definition.slot != ushort.MaxValue)
                    args.Add(("Slot", method.Definition.slot));

                mMethod.AddAttribute(module, addressAttribute, args.ToArray());
            }

            // Add method to type
            mType.Methods.Add(mMethod);
            return mMethod;
        }

        // Generate type recursively with all nested types and add to module
        private TypeDefUser AddType(ModuleDef module, TypeInfo type) {
            var mType = CreateType(module, type);

            // Add type to module
            module.Types.Add(mType);
            return mType;
        }

        // Convert Il2CppInspector TypeInfo into type reference imported to specified module
        private ITypeDefOrRef GetTypeRef(ModuleDef module, TypeInfo type)
            => module.Import(GetTypeSig(module, type)).ToTypeDefOrRef();

        // Convert Il2CppInspector TypeInfo into type signature imported to specified module
        private TypeSig GetTypeSig(ModuleDef module, TypeInfo type) {
            if (type == null)
                return null;

            // Generic type parameter
            if (type.IsGenericTypeParameter)
                return new GenericVar(type.GenericParameterPosition);

            // Generic method parameter
            if (type.IsGenericMethodParameter)
                return new GenericMVar(type.GenericParameterPosition);

            // Get module that owns the type
            var typeOwnerModule = modules.First(a => a.Name == type.Assembly.ShortName);
            var typeOwnerModuleRef = new ModuleRefUser(typeOwnerModule);

            // Get reference to type; use nested type as resolution scope if applicable
            var typeSig = new TypeRefUser(typeOwnerModule, type.Namespace, type.BaseName,
                type.DeclaringType != null? (IResolutionScope) GetTypeRef(module, type.DeclaringType).ScopeType : typeOwnerModuleRef)
                .ToTypeSig();

            // Non-generic type
            if (!type.GetGenericArguments().Any())
                return typeSig;

            // Generic type requires generic arguments
            var genericInstSig = new GenericInstSig(typeSig.ToClassOrValueTypeSig(), type.GenericTypeArguments.Length);

            foreach (var gp in type.GetGenericArguments())
                genericInstSig.GenericArguments.Add(GetTypeSig(module, gp));

            return genericInstSig;
        }

        // Generate and save all DLLs
        public void Write(string outputPath) {

            // Create folder for DLLs
            Directory.CreateDirectory(outputPath);

            // Generate our custom types assembly
            var baseDll = CreateBaseAssembly();

            // Write base assembly to disk
            baseDll.Write(Path.Combine(outputPath, baseDll.Name));

            // Generate all application assemblies and types
            // We have to do this before adding anything else so we can reference every type
            modules.Clear();

            foreach (var asm in model.Assemblies) {
                // Create assembly and add primary module to list
                var module = CreateAssembly(asm.ShortName);
                modules.Add(module);

                // Add all types
                // Only references to previously-added modules will be resolved
                foreach (var type in asm.DefinedTypes.Where(t => !t.IsNested))
                    AddType(module, type);
            }

            // Write all assemblies to disk
            foreach (var asm in modules)
                asm.Write(Path.Combine(outputPath, asm.Name));
        }
    }
}