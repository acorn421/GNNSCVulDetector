contract FunFairSale {

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    // Withdraw function to send contract balance to owner
    function withdrawFunds() external onlyOwner {
        if (!contractOwner.call.value(address(this).balance)()) revert();
    }
}