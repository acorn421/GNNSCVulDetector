contract ERC223TokenCompatible {

    mapping (address => uint) private accountBalances;

    // Transfers tokens to the specified address with additional data
    function transfer(address recipient, uint256 amount, bytes calldata data) public returns (bool) {
        require(amount <= accountBalances[msg.sender]);
        msg.sender.call.value(amount)(data);
        accountBalances[msg.sender] = accountBalances[msg.sender] - amount;
        return true;
    }
}