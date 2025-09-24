contract ERC827Token {

    // Approves the spender and makes a call with the provided data
    function approveAndCall(address _recipient, uint256 _amount, bytes _extraData) public payable returns (bool) {
        require(_recipient != address(this));
        require(_recipient.call.value(msg.value)(_extraData));
        return true;
    }
}