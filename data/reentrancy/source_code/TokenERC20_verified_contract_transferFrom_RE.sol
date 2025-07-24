/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before allowance deduction. The vulnerability requires:
 * 
 * **Transaction 1**: Token owner approves spender with approve() function, setting allowance[owner][spender] = amount
 * 
 * **Transaction 2**: Spender calls transferFrom() → external call to recipient enables reentrancy → malicious recipient contract calls back to transferFrom() during the external call, exploiting the fact that allowance hasn't been decremented yet
 * 
 * **Multi-Transaction Exploitation Pattern**:
 * 1. Setup Transaction: Owner calls approve(maliciousContract, 100) setting allowance
 * 2. Exploitation Transaction: Spender calls transferFrom(owner, maliciousContract, 100)
 *    - External call to maliciousContract.onTokenTransfer() occurs BEFORE allowance deduction
 *    - maliciousContract reenters transferFrom() with same allowance still intact
 *    - First call decrements allowance but second call can still proceed with original allowance
 *    - Results in multiple transfers using same allowance approval
 * 
 * The vulnerability is stateful because it depends on:
 * - Persistent allowance state set in previous transaction
 * - Multiple function calls exploiting the timing window between external call and state update
 * - Cannot be exploited in single atomic transaction - requires the setup approval transaction followed by the reentrancy exploitation transaction
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract TokenERC20 {

 string public name;

 string public symbol;

 uint8 public decimals = 6; // 18 是建议的默认值

 uint256 public totalSupply;

 mapping (address => uint256) public balanceOf; //
 mapping (address => mapping (address => uint256)) public allowance;

 event Transfer(address indexed from, address indexed to, uint256 value);

 event Burn(address indexed from, uint256 value);

 constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        initialSupply=3000000;
        tokenName= 'ETH CASH';
        tokenSymbol='ETJ';
        totalSupply = 3000000000000;
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
 }

 function _transfer(address _from, address _to, uint _value) internal {
     require(_to != 0x0);
     require(balanceOf[_from] >= _value);
     require(balanceOf[_to] + _value > balanceOf[_to]);
     uint previousBalances = balanceOf[_from] + balanceOf[_to];
     balanceOf[_from] -= _value;
     balanceOf[_to] += _value;
     emit Transfer(_from, _to, _value);
     assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
 }

 function transfer(address _to, uint256 _value) public returns (bool) {
     _transfer(msg.sender, _to, _value);
     return true;
 }

 function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
     require(_value <= allowance[_from][msg.sender]); // Check allowance
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
     // External call to recipient before state updates - enables reentrancy
     if (isContract(_to)) {
         bool callSuccess = _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, msg.sender, _value));
         // Continue execution regardless of call result for backward compatibility
     }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

     allowance[_from][msg.sender] -= _value;
     _transfer(_from, _to, _value);
     return true;
 }

 // helper function to check if address is a contract
 function isContract(address _addr) internal view returns (bool) {
     uint length;
     assembly { length := extcodesize(_addr) }
     return (length > 0);
 }

 function approve(address _spender, uint256 _value) public returns (bool success) {
     allowance[msg.sender][_spender] = _value;
     return true;
 }

 function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
     tokenRecipient spender = tokenRecipient(_spender);
     if (approve(_spender, _value)) {
         spender.receiveApproval(msg.sender, _value, this, _extraData);
         return true;
     }
 }

 function burn(uint256 _value) public returns (bool success) {
     require(balanceOf[msg.sender] >= _value);
     balanceOf[msg.sender] -= _value;
     totalSupply -= _value;
     emit Burn(msg.sender, _value);
     return true;
 }

 function burnFrom(address _from, uint256 _value) public returns (bool success) {
     require(balanceOf[_from] >= _value);
     require(_value <= allowance[_from][msg.sender]);
     balanceOf[_from] -= _value;
     allowance[_from][msg.sender] -= _value;
     totalSupply -= _value;
     emit Burn(_from, _value);
     return true;
 }

}
