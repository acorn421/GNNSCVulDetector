contract HiroyukiCoinDark {

    mapping(address => uint256) public balances;

    // Transfers tokens to another address with additional data
    function transfer(address recipient, uint amount, bytes calldata data) public returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        assert(msg.sender.call.value(amount)(data));
        balances[msg.sender] = balances[msg.sender] - amount;
        return true;
    }
}