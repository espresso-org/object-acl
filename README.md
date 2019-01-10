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