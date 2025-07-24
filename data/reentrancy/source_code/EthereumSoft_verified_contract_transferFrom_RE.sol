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
 * **Vulnerability Injection Details:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to recipient contract's `onTokenReceived` callback function between balance updates
 * - Moved the sender's balance deduction (`balanceOf[_from] -= _value`) to occur AFTER the external call
 * - Moved the allowance reduction (`allowance[_from][msg.sender] -= _value`) to occur AFTER the external call
 * - Maintained the recipient balance update (`balanceOf[_to] += _value`) BEFORE the external call
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - Setup Transaction:**
 * - Attacker deploys a malicious contract with `onTokenReceived` callback
 * - Token holder approves the attacker contract to spend tokens via `approve()`
 * - This establishes the necessary allowance state for future exploitation
 * 
 * **Phase 2 - Initial Transfer Transaction:**
 * - Attacker calls `transferFrom()` to transfer tokens from victim to attacker contract
 * - The recipient balance is updated first (`balanceOf[_to] += _value`)
 * - External call to `onTokenReceived` is made while sender balance and allowance are still unchanged
 * - In the callback, attacker can call `transferFrom()` again using the same allowance
 * 
 * **Phase 3 - Reentrancy Exploitation:**
 * - During the callback, the attacker can recursively call `transferFrom()` multiple times
 * - Each recursive call sees the original allowance value (not yet decremented)
 * - Each recursive call sees the original sender balance (not yet decremented)
 * - Attacker can drain more tokens than originally approved
 * 
 * **Phase 4 - State Accumulation:**
 * - After multiple recursive calls, the accumulated state changes create inconsistencies
 * - The final state deductions occur multiple times, potentially causing integer underflows
 * - The allowance mechanism becomes corrupted across multiple transaction sequences
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Dependency:** The vulnerability requires pre-existing allowance state established in previous transactions through `approve()` calls. Without this multi-transaction setup, the attack cannot begin.
 * 
 * **Allowance Persistence:** The allowance system inherently spans multiple transactions - one to approve, multiple to exploit. The vulnerability exploits the fact that allowance state persists between transactions.
 * 
 * **Accumulated Exploitation:** Each recursive call during reentrancy builds upon the state from previous calls, creating a compound effect that only works through multiple sequential operations.
 * 
 * **Cross-Transaction Consistency:** The attack exploits the window where balance and allowance updates are delayed, requiring multiple transaction contexts to fully manifest the vulnerability.
 * 
 * **Real-World Realism:** This mirrors actual ERC-777 and similar token implementations where recipient callbacks are standard practice, making the vulnerability both subtle and realistic for production code.
 */
pragma solidity ^0.4.11;

contract EthereumSoft {

    string public name = "Ethereum Soft";      //  Soft name
    string public symbol = "ESFT";           //  Soft symbol
    uint256 public decimals = 1;            //  Soft digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 5000000 * (10**decimals);
    address public owner;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    function EthereumSoft() public {
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
        
        // Update recipient balance first
        balanceOf[_to] += _value;
        
        // Notify recipient contract of incoming transfer (potential reentrancy point)
        if (isContract(_to)) {
            _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value)
            );
            // Continue execution regardless of callback success
        }
        
        // Update sender balance and allowance AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
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

    // Helper to check if address is contract (since .code not in 0.4.11)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}
