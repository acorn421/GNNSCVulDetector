contract XToken {
 mapping(address => uint256) public balances;
 
 function transfer(address _to, uint256 _value, bytes memory _data, string memory _custom_fallback) public returns (bool) {
 require(balances[msg.sender] >= _value, "no enough token");
 
 (bool success,) = _to.call(abi.encodeWithSignature(_custom_fallback, msg.sender, _value, _data));
 require(success, "transfer failed");
 
 balances[msg.sender] -= _value;
 balances[_to] += _value;
 
 return true;
 }
}