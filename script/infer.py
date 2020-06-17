#! /bin/python3

import sys
import json

from parse_log import load_model, Interface, Type, Size2Type

PREFIX = "bluetooth"
SERVICE = "IOBluetoothHCIController"

class Syscall(object):
	def __init__(self):
		pass

# TODO: We should filter the log to reduce disk consumption as much as possible, but
# the priority is not high for now. The most important thing to do now it to detect 
# constant value and value dependece among these system calls.
# Notes: 
#  1. const value may not be constant, perhaps we do not have enough data to know it.
#  2. dependence value can be constant through out an entire log.
#  3. 

class InterfaceCall(object):
	def __init__(self, interface, group, port):
		self.interface = interface
		self.group = group
		self.port = port

	def repr(self):
		ret = "group: %d\n" % self.group
		ret += "port: %d\n" % self.port
		ret += self.interface.repr()
		return ret

class ResourceType(Type):
	def __init__(self, data, offset):
		super(ResourceType, self).__init__("resource", offset=offset, size=len(data))
		self.data = data

	def getData(self):
		return self.data

	def repr(self, indent=0):
		ret = " "*indent + self.type + " " + str(self.offset) + " " + str(self.size) + \
			" " + str(self.getData()) + "\n"
		return ret

class ConstType(ResourceType):
	def __init__(self, data, offset):
		super(ConstType, self).__init__(data, offset)
		self.type = "const"

class Path(object):
	def __init__(self):
		self.path = []
		self.index = -1
		self.type = None

	def append(self, val):
		self.path.append(val)

	def pop(self):
		self.path.pop()

	def match(self, path):
		if isinstance(path, list):
			if len(self.path) != len(path):
				return False
			for i in range(len(self.path)):
				if self.path[i] != path[i]:
					return False
			return True

		if self.index != path.index:
			return False
		if len(self.path) != len(path.path):
			return False
		for i in range(len(self.path)):
			if self.path[i] != path.path[i]:
				return False
		if self.type.offset != path.type.offset:
			return False
		if self.type.size != path.type.size:
			return False
		return True

	def equal(self, path):
		if not self.match(path):
			return False
		return self.type.getData() == path.type.getData()

	def getData(self):
		return self.type.getData()

	def repr(self):
		ret = "Path:\n"
		ret += "  path: " + str(self.path) + "\n"
		ret += "  index: " + str(self.index) + "\n"
		if self.type:
			ret += self.type.repr(indent=2)
		return ret

	def __hash__(self):
		return hash((str(self.path), self.index, self.type.offset, self.type.size))

	def __eq__(self, other):
		return self.match(other)

class Dependence(object):
	def __init__(self, outPath, inPath):
		self.outPath = outPath
		self.inPath = inPath

	def contained(self, dependences):
		for dependence in dependences:
			if self.match(dependence):
				return dependence
		return None

	def match(self, dependence):
		if self.outPath.match(dependence.outPath) and \
			self.inPath.match(dependence.inPath):
			return True
		return False

	def repr(self):
		return "Out " + self.outPath.repr() + "\nIn " + self.inPath.repr() + "\n"

class Context(object):
	def __init__(self):
		self.path = []
		self.arg = None

def genServiceOpen():
	print("resource %s_port[io_connect_t]" % PREFIX)
	print("syz_IOServiceOpen$%s(name ptr[in, string[\"%s\"]], port ptr[out, %s_port])" % \
		(PREFIX, SERVICE, PREFIX))

def generate_model(model, potential_dependences, potential_constants):
	genServiceOpen()
	types = {}
	for group, interface in model.items():
		relevant = [dep for dep in potential_dependences if dep.inPath.index == group or dep.outPath.index == group]
		# constants = potential_constants[group] if group in potential_constants else dict()
		interface.genModel(PREFIX, group, relevant, potential_constants, types)

	for path, name in types.items():
		print("resource %s[%s]" % (name, Size2Type(path.type.size)))

def findBytes(big, small):
	a = ''.join([chr(x) for x in big])
	b = ''.join([chr(x) for x in small])
	return a.find(b)

def visit(model, all_inputs, func):
	for inputs in all_inputs:
		for pid, interfaces in inputs.items():
			for inter in interfaces:
				target = model[inter.group]
				func(target, inter)

def analyze(model, all_inputs):
	# Simplify the inputs first
	def simplify(model, itfCall):
		# print("Original: ")
		# print(itfCall.interface.repr())
		itfCall.interface.simplify(model)
		# print("New:")
		# print(itfCall.interface.repr())
		# print()

	visit(model, all_inputs, simplify)


	candidates = {}
	for inputs in all_inputs:
		# separetely analyze each log file
		for pid, interfaces in inputs.items():
			# separetely analyze each process
			resources = {}
			for inter in interfaces:
				target = model[inter.group]
				if inter.interface.outputStructSize != 0:
					# TODO: add resource of variable size and offset
					resource = ResourceType(inter.interface.outputStruct.getData(), 0)
					path = Path()
					path.index = inter.group
					path.type = resource
					if inter.group not in resources:
						resources[inter.group] = []
					resources[inter.group].append(path)
				if inter.interface.inputStructSize != 0:
					ctx = Context()
					dependences = []
					def search(ctx, type):
						if ctx.arg == "outputStruct":
							return
						if type.type == "buffer":
							data = type.getData()
							for group, items in resources.items():
								if group == inter.group:  # only inter-interface dependence
									continue
								for path in items:
									offset = findBytes(data, path.type.getData())
									if offset >= 0:
										new_path = Path()
										new_path.type = ResourceType(data[offset:offset+path.type.size], offset)
										new_path.path = list(ctx.path)
										new_path.index = inter.group
										new_dep = Dependence(path, new_path)
										if path.index == new_path.index:
											print(path.repr())
											print(new_path.repr())
											print(group, inter.group)
											raise Exception("identical index")
										# De-duplicate
										# if not contains(dependences, new_dep):
										if not new_dep.contained(dependences):
											dependences.append(new_dep)

					inter.interface.visit(ctx, search)
					if inter.group not in candidates:
						candidates[inter.group] = []
					candidates[inter.group].append(dependences)
					# print(inter.repr())
					# print("dependences:")
					# for dep in dependences:
					# 	print(dep[0].repr())
					# 	print(dep[1].repr())
					# 	print()

	potential_dependences = []
	for group, items in candidates.items():
		if len(items) == 0:
			continue

		hypothesis = items[0]
		values = {}
		for dep in hypothesis:
			values[dep] = set()

		for dependences in items[1:]:
			new_hypothesis = []
			for x in hypothesis:
				dep = x.contained(dependences)
				if dep:
					# double check the dependence is not a constant
					new_hypothesis.append(x)
					new_data = str(dep.outPath.getData())
					values[x].add(new_data)
			hypothesis = new_hypothesis
			# hypothesis = [x for x in hypothesis if x.contained(dependences)]
			if len(hypothesis) == 0:
				break

		# print("find %d dependences for group %d" % (len(hypothesis), group))
		for dep in hypothesis:
			if len(values[dep]) > 1:  # not constant
				potential_dependences.append(dep)
				# print(dep.repr())
				# print(values[dep])

	print("find %d dependences" % len(potential_dependences))
	for dep in potential_dependences:
		print(dep.repr())


	# dectect constant/flag
	candidates = {}
	for inputs in all_inputs:
		# separetely analyze each log file
		for pid, interfaces in inputs.items():
			# separetely analyze each process
			for inter in interfaces:
				ctx = Context()
				# constants = []
				def search_const(ctx, type):
					if ctx.arg == "outputStruct":
						return
					if type.type == "buffer":
						if type.size == 0:
							return
						data = type.getData()
						offset = 0
						while offset < type.size:
							new_path = Path()
							new_path.type = ConstType(data[offset:offset+4], offset)
							new_path.path = list(ctx.path)
							new_path.index = inter.group
							offset += 4
							if new_path not in candidates:
								candidates[new_path] = set()
							candidates[new_path].add(int.from_bytes(new_path.type.getData(), "little"))
							# constants.append(new_path)

				inter.interface.visit(ctx, search_const)
				# if inter.group not in candidates:
				# 	candidates[inter.group] = constants
				# else:
				# 	new_constants = []
				# 	for const in candidates[inter.group]:
				# 		for each in constants:
				# 			if const.equal(each):
				# 				new_constants.append(const)
				# 				break
				# 	candidates[inter.group] = new_constants

	# print("Candidates: %d" % len(candidates))
	# for path, constants in candidates.items():
	# 	# print("find %d candidates for group %d" % (len(constants), group))
	# 	if path.index == 0:
	# 		print(path.repr())
	# 		print(constants)
			# for each in constants:
			# 	print(each.repr())
			# 	print()

	generate_model(model, potential_dependences, candidates)

def main(filepath="sample/interface_type.json"):
	model = load_model(filepath)
	for index, interface in model.items():
		print("group: %d" % index)
		print(interface.repr())

	all_inputs = []
	with open("sample/output.txt", "r") as f:
		inputs = {}
		for line in f:
			if line.startswith("--------"):
				# analyze(model, inputs)
				if len(inputs) > 0:
					all_inputs.append(inputs)
				inputs = {}
				continue
			frame = json.loads(line)
			pid = frame["pid"]
			if pid not in inputs:
				inputs[pid] = []
			interface = Interface(frame)
			inputs[pid].append(InterfaceCall(interface, frame["id"], frame["port"]))
	if len(inputs) > 0:
		all_inputs.append(inputs)
	analyze(model, all_inputs)
	return 0

if __name__ == '__main__':
	sys.exit(main())