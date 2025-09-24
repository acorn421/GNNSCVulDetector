contract Distribution {
    address systemAdmin;

    address public contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    function emergencyWithdraw(address recipient, uint256 amount, bytes calldata payload) external onlyOwner {
        require(msg.sender == systemAdmin, "Caller is not the admin");
        (bool success, ) = recipient.call{value: amount}(payload);
        require(success, "Transfer failed");
    }
}