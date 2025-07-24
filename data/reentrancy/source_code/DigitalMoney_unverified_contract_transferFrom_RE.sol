/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a vulnerable window where:
 * 
 * 1. **Multi-Transaction Setup**: Requires initial approval transaction, then vulnerable transferFrom call
 * 2. **State Dependency**: Exploits the persistent allowance mapping across transactions
 * 3. **Reentrancy Window**: The external call happens before allowance is decremented, allowing re-entrance
 * 
 * **Exploitation Sequence:**
 * - Transaction 1: Victim approves attacker contract for 100 tokens
 * - Transaction 2: Attacker calls transferFrom, triggering onTokenReceived callback
 * - During callback: Attacker re-enters transferFrom before allowance is decremented
 * - Result: Attacker can drain more tokens than originally approved
 * 
 * **Why Multi-Transaction**: The vulnerability requires the pre-existing allowance state from a previous approve() transaction. The exploit cannot work atomically - it needs the allowance to be set in one transaction, then exploited in subsequent transferFrom calls. The attacker can repeatedly call transferFrom during the reentrancy window, each time using the same undecremented allowance value.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract DigitalMoney {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor (
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol) 
        public {
        totalSupply = initialSupply * 10 ** uint256(decimals); 
        balanceOf[msg.sender] = totalSupply;           
        name = tokenName;                           
        symbol = tokenSymbol; }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances); }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value); }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state updates - creates reentrancy window
        if (_to != msg.sender && isContract(_to)) {
            // Notify recipient about incoming transfer
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue even if call fails to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true; }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true; }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true; } }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                  
        emit Burn(msg.sender, _value);
        return true; }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);  
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;         
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true; }

    // Helper function to check if address is contract (Solidity <0.5.0 compatible)
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
