/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the token holder before state updates. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where:
 * 
 * 1. **Checks**: require statements validate conditions
 * 2. **Interactions**: External call to tokenRecipient interface 
 * 3. **Effects**: State variables are updated after the external call
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements tokenRecipient interface and gets approved allowance from a victim.
 * 
 * **Transaction 2 (Initial Burn)**: Attacker calls burnFrom() which triggers the external call to their malicious contract's receiveApproval function.
 * 
 * **During Callback (Same Transaction 2)**: The malicious contract's receiveApproval function calls burnFrom() again while the original state updates haven't occurred yet, allowing the attacker to burn more tokens than their allowance should permit.
 * 
 * **Transaction 3+ (Accumulation)**: The attacker can repeat this process across multiple transactions, each time exploiting the temporary inconsistent state where checks pass but effects haven't been applied yet.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires setting up the malicious contract first (Transaction 1)
 * - Each exploitation requires a separate transaction that triggers the reentrancy (Transaction 2+)
 * - The accumulated effect of multiple exploitations across transactions allows draining more tokens than should be possible
 * - The state changes (balanceOf, allowance) persist between transactions, enabling progressive exploitation
 * 
 * The key insight is that the external call happens after validation but before state updates, creating a window where the same allowance can be exploited multiple times across different transactions through reentrancy.
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


    constructor(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify token holder about burn - external call before state updates
        if (_from != msg.sender && _from != address(0)) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;         
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true; }
}