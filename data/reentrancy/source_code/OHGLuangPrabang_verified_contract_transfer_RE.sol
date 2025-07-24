/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before the Transfer event. The vulnerability requires an attacker to deploy a malicious contract that implements the onTokenReceived function to recursively call transfer() across multiple transactions, exploiting the persistent state changes in the balances mapping. This creates a classic reentrancy scenario where the external call occurs after state modifications, violating the Checks-Effects-Interactions pattern.
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the recipient address using `_to.code.length > 0`
 * 2. Inserted an external call `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)` after balance updates
 * 3. Positioned the external call after state modifications but before the Transfer event
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - Transaction 1: User calls transfer() to malicious contract, balances are updated, external call triggers
 * - During callback: Malicious contract's onTokenReceived() initiates another transfer() call
 * - Transaction 2+: Subsequent transfers can be made while the original caller's balance was already decremented
 * - The persistent state in the balances mapping allows the attacker to drain tokens across multiple transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the persistent state changes in the balances mapping across transaction boundaries
 * - Each recursive call creates a new transaction context where balances have been modified by previous calls
 * - The attacker needs to set up a malicious contract beforehand (separate transaction)
 * - The exploitation requires coordination between the initial transfer and the callback mechanism across multiple blockchain transactions
 * - The accumulated effect of balance modifications across transactions enables the complete exploitation
 */
pragma solidity ^0.4.11;
contract OHGLuangPrabang {
    
    uint public constant _totalSupply = 150000000000000000000000000;
    
    string public constant symbol = "OHGLP";
    string public constant name = "OHG Luang Prabang";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    function OHGLuangPrabang() public {
        balances[msg.sender] = _totalSupply;
    }
    
    function totalSupply() public constant returns (uint256 supply) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner]; 
    }
    
    function transfer (address _to, uint256 _value) public returns (bool success) {
        require(    
            balances[msg.sender] >= _value
            && _value > 0 
        );
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract of incoming transfer
        if (isContract(_to)) {
            // External call to recipient contract after state updates
            _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed [_from][msg.sender] -= _value;
        Transfer (_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function isContract(address _addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 
}
