/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * **Vulnerability Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added `pendingBurns` mapping to track accumulated burn amounts across transactions
 * - Added `burnNotificationContract` address for external callback system
 * - Introduced external call to `IBurnNotification.notifyBurn()` BEFORE state updates
 * - Added `IBurnNotification` interface for the callback contract
 * - State modifications (`balanceOf` and `totalSupply`) now occur AFTER the external call
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker calls `burn(100)` with malicious notification contract
 * - `pendingBurns[attacker] = 100` (state persists)
 * - External call triggers malicious contract
 * - Malicious contract can read `pendingBurns[attacker] = 100` but tokens haven't been burned yet
 * - Attacker's `balanceOf` is still unchanged at this point
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `burn(50)` again
 * - `pendingBurns[attacker] = 150` (accumulated from previous transaction)
 * - External call sees `totalPending = 150` but only `currentBurn = 50`
 * - Malicious contract can exploit the discrepancy between pending burns and actual balance
 * - Can potentially call back into `burn()` or other functions while state is inconsistent
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - Each subsequent burn call accumulates more pending burns
 * - The attacker can exploit the time window between external call and state update
 * - Can potentially drain tokens or manipulate contract state through repeated reentrancy
 * 
 * **3. Why Multi-Transaction Dependency is Essential:**
 * 
 * **State Accumulation Requirement:**
 * - The `pendingBurns` mapping accumulates values across multiple transactions
 * - Single transaction exploitation is prevented because the vulnerability depends on accumulated state from previous calls
 * - The attacker needs to build up pending burn amounts over multiple transactions to create exploitable conditions
 * 
 * **Persistent State Vulnerability:**
 * - Each transaction leaves persistent state in `pendingBurns` mapping
 * - This persistent state becomes the attack vector for subsequent transactions
 * - The reentrancy vulnerability compounds with each transaction, making it more exploitable
 * 
 * **Time-Based Exploitation:**
 * - The vulnerability requires the attacker to observe and exploit the gap between external calls and state updates across multiple transactions
 * - Single transaction attacks are ineffective because the full exploitation requires accumulated pending burns from previous transactions
 * 
 * **Cross-Transaction State Manipulation:**
 * - The malicious notification contract can track state changes across multiple burn operations
 * - This allows for sophisticated attacks that manipulate the contract's internal accounting over time
 * - The vulnerability becomes more severe as more transactions accumulate pending burns
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to fully exploit, making it particularly dangerous as it can compound over time and harder to detect in single-transaction analysis.
 */
pragma solidity ^0.4.16;
 /**
     * B2AND Token contract
     *
     * The final version 2018-02-18
*/
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract Ownable {
    address public owner;
    function Ownable() public {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Interface for burn notification contract (MOVED OUTSIDE contract)
interface IBurnNotification {
    function notifyBurn(address burner, uint256 currentBurn, uint256 totalPending) external;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
contract B2ANDcoin is Ownable {
    string public name;
    string public symbol;
    uint8 public decimals = 18;   
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    function B2ANDcoin(
    ) public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;               
        name = "B2ANDcoin";                                
        symbol = "B2C";                  
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
        require(_value <= allowance[_from][msg.sender]);    
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // State variable to track burn operations (add to contract state)
    mapping(address => uint256) public pendingBurns;
    address public burnNotificationContract;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add to pending burns for multi-transaction tracking
        pendingBurns[msg.sender] += _value;
        // External call to notification contract BEFORE state updates
        if (burnNotificationContract != address(0)) {
            // This external call can trigger reentrancy
            IBurnNotification(burnNotificationContract).notifyBurn(msg.sender, _value, pendingBurns[msg.sender]);
        }
        // State updates happen AFTER external call (vulnerability)
        balanceOf[msg.sender] -= _value;           
        totalSupply -= _value;
        // Clear pending burns only after successful burn
        pendingBurns[msg.sender] = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
