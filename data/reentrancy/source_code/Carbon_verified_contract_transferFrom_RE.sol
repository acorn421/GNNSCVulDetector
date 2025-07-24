/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **VULNERABILITY INJECTION EXPLANATION:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to `_to` address using low-level `call()` after balance updates but before allowance decrement
 * - Introduced `onTokenReceived` callback pattern (common in modern token implementations)
 * - Moved allowance update to occur AFTER the external call, creating a critical reentrancy window
 * - Added code length check to only call contracts (realistic defensive programming)
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup:**
 * - Attacker deploys malicious contract with `onTokenReceived` function
 * - Attacker gets approved allowance from victim account
 * - State: `allowance[victim][attacker] = 1000 tokens`
 * 
 * **Transaction 2 - Initial Transfer:**
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)`
 * - Balances updated: `balanceOf[victim] -= 500`, `balanceOf[maliciousContract] += 500`
 * - External call triggers `maliciousContract.onTokenReceived()`
 * - **CRITICAL**: At this point, `allowance[victim][attacker]` is still 1000 (not yet decremented)
 * 
 * **Transaction 3 - Reentrancy Exploitation:**
 * - Inside `onTokenReceived`, malicious contract calls `transferFrom(victim, anotherAddress, 500)` 
 * - This succeeds because allowance is still 1000 (persistent state from previous transaction)
 * - Attacker has now transferred 1000 tokens using only 1000 allowance
 * - Only after this completes does the original allowance get decremented
 * 
 * **3. Why Multi-Transaction Requirement:**
 * 
 * **State Persistence Between Calls:**
 * - The allowance state persists between the external call and the allowance update
 * - This creates a window where the same allowance can be used multiple times
 * - The vulnerability requires the external contract to make additional calls, creating a chain of transactions
 * 
 * **Accumulated State Exploitation:**
 * - Each reentrancy call exploits the fact that allowance hasn't been decremented yet
 * - Multiple transfers can occur before the allowance is finally updated
 * - The total transferred amount exceeds the original allowance due to state inconsistency
 * 
 * **Cannot Be Exploited in Single Transaction:**
 * - A single atomic transaction would either complete all state updates or revert entirely
 * - The vulnerability specifically requires the persistent state inconsistency between balance updates and allowance updates
 * - Multiple function calls are necessary to accumulate the exploitative effect
 * 
 * **4. Realistic Implementation:**
 * - Token receiver notifications are common in modern ERC20 implementations
 * - The callback pattern is seen in protocols like ERC777 and many DeFi tokens
 * - The vulnerability follows real-world patterns where external calls are added for functionality but create security gaps
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

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    function Carbon() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it has code - VULNERABILITY INJECTION
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call before allowance update creates reentrancy window
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
        }
        
        // Update allowance after external call - DELAYED STATE UPDATE
        allowance[_from][msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function setName(string _name) public isOwner 
    {
        name = _name;
    }
    function burnSupply(uint256 _amount) public isOwner
    {
        balanceOf[owner] -= _amount;
        emit SupplyBurn(_amount);
    }
    function burnTotalSupply(uint256 _amount) public isOwner
    {
        totalSupply-= _amount;
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event SupplyBurn(uint256 _amount);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}