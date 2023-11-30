using NoisyCowStudios.Bin2Object;
using System.Text;
using System;

namespace Il2CppInspector.Utils;

public static class BlobReader
{
    public static object GetConstantValueFromBlob(Il2CppInspector inspector, Il2CppTypeEnum type, BinaryObjectStream blob)
    {
        const byte kArrayTypeWithDifferentElements = 1;

        object value = null;

        switch (type)
        {
            case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                value = blob.ReadBoolean();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_U1:
            case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                value = blob.ReadByte();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                // UTF-8 character assumed
                value = BitConverter.ToChar(blob.ReadBytes(2), 0);
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                value = blob.ReadUInt16();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                value = blob.ReadInt16();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                value = blob.Version >= 29
                    ? blob.ReadCompressedUInt32()
                    : blob.ReadUInt32();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                value = blob.Version >= 29
                    ? blob.ReadCompressedInt32()
                    : blob.ReadInt32();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                value = blob.ReadUInt64();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                value = blob.ReadInt64();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                value = blob.ReadSingle();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                value = blob.ReadDouble();
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                var uiLen = blob.Version >= 29
                    ? blob.ReadCompressedInt32()
                    : blob.ReadInt32();

                if (uiLen != -1)
                    value = Encoding.UTF8.GetString(blob.ReadBytes(uiLen));

                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                var length = blob.Version >= 29
                ? blob.ReadCompressedInt32()
                : blob.ReadInt32();

                if (length == -1)
                    break;

                var arrayElementType = ReadEncodedTypeEnum(inspector, blob, out var arrayElementDef);
                var arrayElementsAreDifferent = blob.ReadByte();

                if (arrayElementsAreDifferent == kArrayTypeWithDifferentElements)
                {
                    var array = new ConstantBlobArrayElement[length];
                    for (int i = 0; i < length; i++)
                    {
                        var elementType = ReadEncodedTypeEnum(inspector, blob, out var elementTypeDef);
                        array[i] = new ConstantBlobArrayElement(elementTypeDef, GetConstantValueFromBlob(inspector, elementType, blob));
                    }

                    value = new ConstantBlobArray(arrayElementDef, array);
                }
                else
                {
                    var array = new object[length];
                    for (int i = 0; i < length; i++)
                    {
                        array[i] = GetConstantValueFromBlob(inspector, arrayElementType, blob);
                    }

                    value = new ConstantBlobArray(arrayElementDef, array);
                }

                break;

            case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
            case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
            case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                break;
            case Il2CppTypeEnum.IL2CPP_TYPE_IL2CPP_TYPE_INDEX:
                var index = blob.ReadCompressedInt32();
                if (index != -1)
                    value = inspector.TypeReferences[index];

                break;


        }

        return value;
    }

    public static Il2CppTypeEnum ReadEncodedTypeEnum(Il2CppInspector inspector, BinaryObjectStream blob,
        out Il2CppTypeDefinition enumType)
    {
        enumType = null;

        var typeEnum = (Il2CppTypeEnum)blob.ReadByte();
        if (typeEnum == Il2CppTypeEnum.IL2CPP_TYPE_ENUM)
        {
            var typeIndex = blob.ReadCompressedInt32();
            enumType = inspector.TypeDefinitions[typeIndex];
            typeEnum = inspector.TypeReferences[enumType.byvalTypeIndex].type;
        }
        // This technically also handles SZARRAY (System.Array) and all others by just returning their system type

        return typeEnum;
    }

    public record ConstantBlobArray(Il2CppTypeDefinition ArrayTypeDef, object[] Elements);

    public record ConstantBlobArrayElement(Il2CppTypeDefinition TypeDef, object value);
}