# ObjectACL

Access Control List for managing object permissions


## How to use

### Import the smart contract

```javascript
import "@espresso-org/object-acl/contracts/ObjectACL.sol";
```

### Create permission on an object

```javascript
bytes32 public constant MY_ROLE = keccak256(abi.encodePacked("MY_ROLE"));

objectAcl.createObjectPermission(
    entity, 
    keccak256(abi.encodePacked("my object")), 
    MY_ROLE, 
    manager
);
```

### Verify object permission

```javascript
bytes32 public constant OBJECT_ROLE = keccak256(abi.encodePacked("OBJECT_ROLE"));

objectAcl.hasObjectPermission(
    entity, 
    keccak256(abi.encodePacked("object", 1)), 
    OBJECT_ROLE
);
```

### Get object's permission manager

```javascript
bytes32 public constant WRITE_ACCESS = keccak256(abi.encodePacked("WRITE_ACCESS"));

objectAcl.getObjectPermissionManager(
    keccak256(abi.encodePacked(34)), 
    WRITE_ACCESS
);
```