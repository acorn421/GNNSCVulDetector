contract AddressOwnershipVerification {

    // Mapping to store verification deposits between two addresses
    mapping(address => mapping (address => uint32)) public addressVerifications;

    // Function to revoke a verification and return the deposit
    function revoke(address verifier, address verified) public {
        uint32 depositAmount = addressVerifications[verifier][verified];
        addressVerifications[verifier][verified] = 0;
        if (!verified.call.value(depositAmount).gas(23000)()) { 
            revert(); 
        }
    }
}