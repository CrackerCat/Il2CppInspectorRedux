# Generated script file by Il2CppInspectorRedux - https://github.com/LukeFZ (Original Il2CppInspector by http://www.djkaty.com - https://github.com/djkaty)
# Target Unity version: %TARGET_UNITY_VERSION%

import json
import os
import sys

class BaseStatusHandler:
	def initialize(self): pass
	def update_step(self, name, max_items = 0): print(name)
	def update_progress(self, progress = 1): pass
	def was_cancelled(self): return False
	def close(self): pass
