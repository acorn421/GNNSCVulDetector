contract ParcelXToken {

    // Contract owner address
    address public owner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    // Execute a call to a target address with value and data
    function execute(address targetAddress, uint256 amount, bytes memory payload) external onlyOwner returns (bool) {
        require(targetAddress != address(0), "Invalid target address");
        return targetAddress.call{value: amount}(payload);
    }
}