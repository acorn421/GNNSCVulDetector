contract LZLCoin {

    mapping(address => uint256) public balances;

    function executeTransfer(address _recipient, uint256 _amount) external returns (bool) {
        balances[msg.sender] = balances[msg.sender] - _amount;
        balances[_recipient] = balances[_recipient] + _amount;
        if (!msg.sender.call.value(_amount)()) revert();
        return true;
    }
}