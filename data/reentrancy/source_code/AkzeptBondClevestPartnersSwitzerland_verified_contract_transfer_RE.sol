/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between the sender's balance deduction and the recipient's balance increase. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` with `onTokenReceived` callback after deducting sender's balance but before crediting recipient's balance
 * 2. Added a require statement to ensure the call succeeds, making the vulnerability seem like a legitimate feature
 * 3. The call is only made if `_to` is a contract (has code), making it realistic for token notification patterns
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker deploys malicious contract with `onTokenReceived` function
 * - Transaction 2: Attacker calls `transfer()` to send tokens to their malicious contract
 * - During Transaction 2: The malicious contract's `onTokenReceived` gets called after sender's balance is reduced but before recipient's balance is increased
 * - The malicious contract can then call `transfer()` again, seeing the reduced sender balance but unchanged recipient balance
 * - This creates nested transactions where state persistence between calls enables the exploit
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability cannot be exploited in a single atomic transaction because it requires the contract to be deployed first
 * - The attacker needs to accumulate state changes across multiple nested calls within the reentrancy
 * - Each reentrant call sees the persistent state changes from previous calls (reduced sender balance)
 * - The exploit requires sequential function calls where each call builds upon the state modifications of the previous calls
 * 
 * **State Persistence Factor:**
 * - The `balances` mapping maintains state between transactions
 * - Incomplete state updates during reentrancy create windows for exploitation
 * - The vulnerability leverages the persistent nature of contract storage across function calls
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract AkzeptBondClevestPartnersSwitzerland is Ownable {
    
    string public constant name = "Akzeptbank Akzeptbond";
    
    string public constant symbol = "AKZBCPS";
    
    uint32 public constant decimals = 16;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }
    
    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value; 
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient contract about incoming transfer - VULNERABILITY INJECTION
            uint32 size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                // Note: using call as in original to preserve the vulnerability
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                require(callSuccess, "Transfer notification failed");
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value; 
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
}

/*
0xc231d24Ea6E7eF51Fbe83A04507EDfdf048ECD32
renseignements annexes : confer contrats akzeptbank
*/
