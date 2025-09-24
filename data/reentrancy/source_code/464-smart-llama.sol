contract Escrow {

    // Tracks balances for each address
    mapping (address => uint) public userBalances;

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this");
        _;
    }

    // Allows owner to withdraw their balance
    function withdrawFunds() external onlyOwner {
        uint currentBalance = userBalances[msg.sender];
        (bool success, ) = msg.sender.call{value: currentBalance}("");
        require(success, "Transfer failed");
        userBalances[msg.sender] = 0;
    }
}