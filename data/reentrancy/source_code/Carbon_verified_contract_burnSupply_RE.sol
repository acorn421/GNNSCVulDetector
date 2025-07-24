/*
 * ===== SmartInject Injection Details =====
 * Function      : burnSupply
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding External Calls**: Two external calls to a `burnTracker` contract are added - one before and one after the state update. This creates a realistic scenario where an external contract tracks burn operations.
 * 
 * 2. **Reentrancy Window**: The second external call (`onBurnCompleted`) occurs after the `balanceOf[owner]` has been updated, creating a reentrancy window where the attacker can call back into `burnSupply` while the current execution is still in progress.
 * 
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker (as owner) calls `burnSupply(1000)`, which triggers `onBurnCompleted` callback
 *    - **Transaction 2**: During the callback, attacker reenters `burnSupply(2000)` before the first call completes
 *    - **Transaction 3**: The reentrant call also triggers its own callback, potentially allowing further exploitation
 * 
 * 4. **State Accumulation**: Each reentrant call modifies `balanceOf[owner]` independently, allowing the attacker to burn more tokens than intended across multiple nested calls. The vulnerability accumulates effects as each call processes its own amount while sharing the same state.
 * 
 * 5. **Realistic Implementation**: The burn tracker concept is realistic - many DeFi protocols use external contracts to track important operations like burns for analytics, governance, or integration with other protocols.
 * 
 * The vulnerability is stateful because:
 * - Each call modifies the persistent `balanceOf[owner]` state
 * - The external contract state can be manipulated between calls
 * - The accumulated burn amounts persist across transaction boundaries
 * - The vulnerability requires the burnTracker to be set (state dependency)
 * 
 * This creates a classic reentrancy pattern where external calls allow attackers to manipulate state across multiple transactions, with each transaction building upon the state changes of previous transactions.
 */
pragma solidity ^0.4.11;

contract Carbon {

    string public name = "Carbon";      //  token name
    string public symbol = "COI";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 1000000000 * (10**decimals);
    address public owner;
    address public burnTracker; // <-- Declared burnTracker as address

    // Interface for BurnTracker contract -- moved outside contract for compatibility with solc 0.4.11
}

interface BurnTracker {
    function onBurnInitiated(uint256 _amount) external;
    function onBurnCompleted(uint256 _amount) external;
}

contract CarbonMain is Carbon {
    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    function CarbonMain() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function setName(string _name) public isOwner 
    {
        name = _name;
    }
    function burnSupply(uint256 _amount) public isOwner
    {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add external call to notify burn tracker before state update
        if (burnTracker != address(0)) {
            BurnTracker(burnTracker).onBurnInitiated(_amount);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[owner] -= _amount;
        SupplyBurn(_amount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call after state update - creates reentrancy window
        if (burnTracker != address(0)) {
            BurnTracker(burnTracker).onBurnCompleted(_amount);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    function burnTotalSupply(uint256 _amount) public isOwner
    {
        totalSupply-= _amount;
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event SupplyBurn(uint256 _amount);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
