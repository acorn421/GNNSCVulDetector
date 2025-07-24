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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts before updating the allowance state. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker first needs to get approval from a token holder (Transaction 1), then deploy a malicious contract that implements ITransferNotification (Transaction 2)
 * 
 * 2. **Exploitation Flow**: 
 *    - Transaction 1: Token holder approves attacker's contract with sufficient allowance
 *    - Transaction 2: Attacker calls transferFrom with their malicious contract as recipient
 *    - During the external call to onTokenTransfer, the malicious contract re-enters transferFrom multiple times
 *    - Each re-entrant call passes the allowance check (since allowance hasn't been decremented yet)
 *    - Multiple transfers occur before the allowance is properly updated
 * 
 * 3. **State Persistence**: The vulnerability relies on the persistent allowance state between transactions and the accumulated effect of multiple re-entrant calls before state updates
 * 
 * 4. **Realistic Context**: The notification mechanism appears legitimate (common in modern tokens for integration with DeFi protocols) but creates a critical vulnerability by violating the CEI pattern
 * 
 * The vulnerability requires multiple transactions to set up (approval + malicious contract deployment + attack) and exploits the persistent allowance state across these transactions.
 */
pragma solidity ^0.4.19;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Declare interface for ITransferNotification for use in transferFrom
interface ITransferNotification {
    function onTokenTransfer(address from, uint256 value, address sender) external;
}
 
contract DFC {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);
 
    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
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
        Transfer(_from, _to, _value);
 
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
 
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract before state changes - VULNERABILITY POINT
        if (isContract(_to)) {
            ITransferNotification(_to).onTokenTransfer(_from, _value, msg.sender);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
 
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
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
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
