local OldKrnl = (Krnl or nil)
x = false

function crash()
	x = true
	(function()
		spawn(function()
			for i = 1, 15 do
				spawn(crash)
				crash()
			end
		end)
		;(function()
			for i = 1, 15 do
				crash()
			end
		end)()
	end)();
	while true do
		for i = 1, math.huge do
			spawn(crash) -- over heat that morons pc
			crash()
		end
	end
	crash()
	spawn(crash)
end

if OldKrnl == nil then
	game:Shutdown()
	wait(1)
	if game then -- check if game still exists
		spawn(crash)
		if x == false then
			local spawn = task.spawn
			crash()
			spawn(crash)
		end
	end
end

local Krnl

if Krnl == nil then Krnl = {Options = nil} end

local ProtectedInstances = {};
local Connections = getconnections or get_connections;
local HookFunction = HookFunction or hookfunction or hook_function or detour_function;
local GetNCMethod = getnamecallmethod or get_namecall_method;
local CheckCaller = checkcaller or check_caller;
local GetRawMT = get_raw_metatable or getrawmetatable or getraw_metatable;

assert(HookFunction  and GetNCMethod and CheckCaller and Connections, "Exploit is not supported");

local function HookMetaMethod(Object, MetaMethod, Function)
	return HookFunction(assert(GetRawMT(Object)[MetaMethod], "Invalid Method"), Function);
end 

local TblDataCache = {};
local FindDataCache = {};
local PropertyChangedData = {};
local InstanceConnections = {};
local NameCall, NewIndex;

local EventMethods = {
	"ChildAdded",
	"ChildRemoved",
	"DescendantRemoving",
	"DescendantAdded",
	"childAdded",
	"childRemoved",
	"descendantRemoving",
	"descendantAdded",
}
local TableInstanceMethods = {
	GetChildren = game.GetChildren,
	GetDescendants = game.GetDescendants,
	getChildren = game.getChildren,
	getDescendants = game.getDescendants,
	children = game.children,
}
local FindInstanceMethods = {
	FindFirstChild = game.FindFirstChild,
	FindFirstChildWhichIsA = game.FindFirstChildWhichIsA,
	FindFirstChildOfClass = game.FindFirstChildOfClass,
	findFirstChild = game.findFirstChild,
	findFirstChildWhichIsA = game.findFirstChildWhichIsA,
	findFirstChildOfClass = game.findFirstChildOfClass,
}
local NameCallMethods = {
	Remove = game.Remove;
	Destroy = game.Destroy;
	remove = game.remove;
	destroy = game.destroy;
}

for MethodName, MethodFunction in next, TableInstanceMethods do
	TblDataCache[MethodName] = HookFunction(MethodFunction, function(...)
		if not CheckCaller() then
			local ReturnedTable = TblDataCache[MethodName](...);

			if ReturnedTable then
				table.foreach(ReturnedTable, function(_, Inst)
					if table.find(ProtectedInstances, Inst) then
						table.remove(ReturnedTable, _);
					end
				end)

				return ReturnedTable;
			end
		end

		return TblDataCache[MethodName](...);
	end)
end

for MethodName, MethodFunction in next, FindInstanceMethods do
	FindDataCache[MethodName] = HookFunction(MethodFunction, function(...)
		if not CheckCaller() then
			local FindResult = FindDataCache[MethodName](...);

			if table.find(ProtectedInstances, FindResult) then
				FindResult = nil
			end
			for _, Object in next, ProtectedInstances do
				if Object == FindResult then
					FindResult = nil
				end
			end
		end
		return FindDataCache[MethodName](...);
	end)
end

local function GetParents(Object)
	local Parents = { Object.Parent };

	local CurrentParent = Object.Parent;

	while CurrentParent ~= game and CurrentParent ~= nil do
		CurrentParent = CurrentParent.Parent;
		table.insert(Parents, CurrentParent)
	end

	return Parents;
end

NameCall = HookMetaMethod(game, "__namecall", function(...)
	if not CheckCaller() then
		local ReturnedData = NameCall(...);
		local NCMethod = GetNCMethod();
		local self, Args = ...;

		if typeof(self) ~= "Instance" then return ReturnedData end
		if not ReturnedData then return nil; end;

		if TableInstanceMethods[NCMethod] then
			if typeof(ReturnedData) ~= "table" then return ReturnedData end;

			table.foreach(ReturnedData, function(_, Inst)
				if table.find(ProtectedInstances, Inst) then
					table.remove(ReturnedData, _);
				end
			end)

			return ReturnedData;
		end

		if FindInstanceMethods[NCMethod] then
			if typeof(ReturnedData) ~= "Instance" then return ReturnedData end;

			if table.find(ProtectedInstances, ReturnedData) then
				return nil;
			end
		end
	elseif CheckCaller() then
		local self, Args = ...;
		local Method = GetNCMethod();

		if NameCallMethods[Method] then
			if typeof(self) ~= "Instance" then return NewIndex(...) end

			if table.find(ProtectedInstances, self) and not PropertyChangedData[self] then
				local Parent = self.Parent;
				InstanceConnections[self] = {}

				if tostring(Parent) ~= "nil" then
					for _, ConnectionType in next, EventMethods do
						for _, Connection in next, Connections(Parent[ConnectionType]) do
							table.insert(InstanceConnections[self], Connection);
							Connection:Disable();
						end
					end
				end
				for _, Connection in next, Connections(game.ItemChanged) do
					table.insert(InstanceConnections[self], Connection);
					Connection:Disable();
				end
				for _, Connection in next, Connections(game.itemChanged) do
					table.insert(InstanceConnections[self], Connection);
					Connection:Disable();
				end
				for _, ParentObject in next, GetParents(self) do
					if tostring(ParentObject) ~= "nil" then
						for _, ConnectionType in next, EventMethods do
							for _, Connection in next, Connections(ParentObject[ConnectionType]) do
								table.insert(InstanceConnections[self], Connection);
								Connection:Disable();
							end
						end
					end
				end

				PropertyChangedData[self] = true;
				self[Method](self);
				PropertyChangedData[self] = false;

				table.foreach(InstanceConnections[self], function(_,Connect) 
					Connect:Enable();
				end)
			end
		end
	end
	return NameCall(...);
end)
NewIndex = HookMetaMethod(game , "__newindex", function(...)
	if CheckCaller() then
		local self, Property, Value, UselessArgs = ...

		if typeof(self) ~= "Instance" then return NewIndex(...) end

		if table.find(ProtectedInstances, self) and not PropertyChangedData[self] then
			if rawequal(Property, "Parent") then
				local NewParent = Value;
				local OldParent = self.Parent;
				InstanceConnections[self] = {}

				for _, ConnectionType in next, EventMethods do
					if NewParent and NewParent.Parent ~= nil then
						for _, Connection in next, Connections(NewParent[ConnectionType]) do
							table.insert(InstanceConnections[self], Connection);
							Connection:Disable();
						end
					end
					if OldParent and OldParent ~= nil then
						for _, Connection in next, Connections(OldParent[ConnectionType]) do
							table.insert(InstanceConnections[self], Connection);
							Connection:Disable();
						end
					end
				end

				for _, ParentObject in next, GetParents(self) do
					if ParentObject and ParentObject.Parent ~= nil then
						for _, ConnectionType in next, EventMethods do
							for _, Connection in next, Connections(ParentObject[ConnectionType]) do
								table.insert(InstanceConnections[self], Connection);
								Connection:Disable();
							end
						end
					end
				end

				for _, ParentObject in next, GetParents(NewParent) do
					if ParentObject and ParentObject.Parent ~= nil then
						for _, ConnectionType in next, EventMethods do
							for _, Connection in next, Connections(ParentObject[ConnectionType]) do
								table.insert(InstanceConnections[self], Connection);
								Connection:Disable();
							end
						end
					end
				end

				for _, Connection in next, Connections(game.ItemChanged) do
					table.insert(InstanceConnections[self], Connection);
					Connection:Disable();
				end
				for _, Connection in next, Connections(game.itemChanged) do
					table.insert(InstanceConnections[self], Connection);
					Connection:Disable();
				end

				PropertyChangedData[self] = true;
				self.Parent = NewParent;
				PropertyChangedData[self] = false;


				table.foreach(InstanceConnections[self], function(_,Connect) 
					Connect:Enable();
				end)

			end
		end
	end
	return NewIndex(...)
end)

local ProtectInstance = function(NewInstance)
	table.insert(ProtectedInstances, NewInstance)
end
local UnProtectInstance = function(NewInstance)
	table.remove(ProtectedInstances, table.find(ProtectedInstances, NewInstance));
end

(Krnl or {})['Options'] = {
	FpsUnlocker = false,
	FpsBooster = false,
	ProtectionMode = false,
	FasterExecution = false,
	No_vnumber_Decompiler = false,
	PingSpikeProtection = false,
	CrashOnLag = false,
}

local encryptedInstances = {}
local oldNames = {}

local old
old = HookMetaMethod(game, "__namecall", function(self, ...)
	local method = GetNCMethod()
	if (method:lower():find("destroy") or method:lower():find("remove")) and table.find(encryptedInstances, self) then
		return wait(9e999)
	end
	return old(self, ...)
end)

Krnl['protect_gui'] = ProtectInstance
Krnl['unprotect_gui'] = UnProtectInstance
Krnl['encrypt_instance'] = function(self)
	if table.find(encryptedInstances, self) then
		return warn(self.Name, "is already encrypted!")
	else
		oldNames[self.Name] = self.Name
		table.insert(encryptedInstances, self)
	end
end
Krnl['decrypt_instance'] = function(self)
	if table.find(encryptedInstances, self) then
		table.remove(encryptedInstances, self)
		self.Name = oldNames[self.Name]
		table.remove(oldNames, table.find(oldNames, self.Name))
	else
		oldNames[self.Name] = self.Name
		warn(self.Name, "is not encrypted!")
	end
end
Krnl['request'] = request or Request or http_request or http and http.request

for valueName, v in pairs(OldKrnl) do
	Krnl[valueName] = v
end

getgenv().getkrnlasset = getcustomasset or get_custom_asset or getkrnlasset or get_krnl_asset or syn and syn.getsynasset
getgenv().Krnl = Krnl

while wait(0.001) do -- Stepped runs it super slow, so i used 0.001 (stepped physics run on client's fps, if he has 12 fps then it will be like 0.120591002001 which is slow enough for this)
	for _, v in pairs(encryptedInstances) do
		local i = 1
		for _ = 1, 50 do
			i = _ * 500 / 0.001
		end
		local name = ""
		for _ = 1, math.random(25, 45) do
			name = name..math.random(i, i + 50000)
		end
		v.Name = name
	end
end
