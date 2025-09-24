contract AddressOwnershipVerification {

    // Mapping to store verification deposits between addresses
    mapping(address => mapping (address => uint32)) public addressVerifications;

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to the owner
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    // Function to revoke a verification and return the deposit
    function revoke(address verifier, address verified) external onlyOwner {
        uint32 depositAmount = addressVerifications[verifier][verified];
        require(verified.call.value(depositAmount).gas(23000)(), "Transfer failed");
        addressVerifications[verifier][verified] = 0;
    }
}