contract TokenStore {

    // Mapping to store token balances for each user and token address
    mapping (address => mapping (address => uint256)) public tokenBalances;

    // Function to withdraw tokens
    function withdraw(uint256 amount) external {
        require(tokenBalances[address(0)][msg.sender] >= amount, "Insufficient balance");
        tokenBalances[address(0)][msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) { revert("Transfer failed"); }
    }
}