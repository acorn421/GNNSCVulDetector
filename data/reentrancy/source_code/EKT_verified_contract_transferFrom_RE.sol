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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability works as follows:
 * 
 * **Key Changes Made:**
 * 1. Added an external call to `_to.call()` that invokes `onTokenReceived()` on the recipient contract
 * 2. Moved the sender's balance deduction and allowance reduction to AFTER the external call
 * 3. Updated recipient's balance BEFORE the external call, creating an inconsistent state window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom(victim, attackerContract, amount)` 
 * 2. **During External Call**: The `attackerContract.onTokenReceived()` is triggered while `balanceOf[_from]` and `allowance[_from][msg.sender]` are still unchanged
 * 3. **Reentrancy**: Inside `onTokenReceived()`, the attacker can call `transferFrom()` again with the same parameters
 * 4. **State Inconsistency**: The allowance check passes because `allowance[_from][msg.sender]` hasn't been decremented yet
 * 5. **Accumulated Effect**: Multiple reentrancy calls can drain the victim's balance beyond the original allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance must be set up in a previous transaction via `approve()`
 * - The exploit requires the attacker to deploy a malicious contract that implements `onTokenReceived()`
 * - Each recursive call operates on persistent state that accumulates across the call stack
 * - The vulnerability exploits the time window between balance credit and allowance deduction
 * 
 * **Realistic Nature:**
 * - Token transfer notifications are common in modern tokens (similar to ERC-777 hooks)
 * - The external call pattern appears legitimate for notifying recipients
 * - The state update ordering seems reasonable but creates a critical vulnerability window
 */
pragma solidity ^0.4.16;

contract EKT {

    string public name = "EDUCare";      //  token name
    string public symbol = "EKT";           //  token symbol
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;

    address owner = 0x0;

    uint256 constant valueTotal = 10 * 10000 * 10000 * 100000000;  //总量 10亿
    uint256 constant valueFounder = valueTotal / 100 * 50;  // 基金会50%
    uint256 constant valueSale = valueTotal / 100 * 15;  // ICO 15%
    uint256 constant valueVip = valueTotal / 100 * 20;  // 私募 20%
    uint256 constant valueTeam = valueTotal / 100 * 15;  // 团队与合作伙伴 15%

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier validAddress(address _address) {
        assert(0x0 != _address);
        _;
    }

    // Changed constructor style to be compatible with Solidity 0.4.16
    function EKT(address _founder, address _sale, address _vip, address _team)
        public
        validAddress(_founder)
        validAddress(_sale)
        validAddress(_vip)
        validAddress(_team)
    {
        owner = msg.sender;
        totalSupply = valueTotal;

        // 基金会
        balanceOf[_founder] = valueFounder;
        Transfer(0x0, _founder, valueFounder);

        // ICO
        balanceOf[_sale] = valueSale;
        Transfer(0x0, _sale, valueSale);

        // 私募
        balanceOf[_vip] = valueVip;
        Transfer(0x0, _vip, valueVip);

        // 团队
        balanceOf[_team] = valueTeam;
        Transfer(0x0, _team, valueTeam);

    }

    function transfer(address _to, uint256 _value)
        public
        validAddress(_to)
        returns (bool success)
    {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value)
        public
        validAddress(_from)
        validAddress(_to)
        returns (bool success)
    {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balanceOf[_to] += _value;
        
        // Notify recipient about incoming transfer (VULNERABILITY: External call before state finalization)
        if (isContract(_to)) {
            // Call external contract - this creates reentrancy opportunity
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
            // Continue execution regardless of external call result
        }
        
        // Complete state updates after external call (VULNERABILITY: State updates after external interaction)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
        public
        validAddress(_spender)
        returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Helper to check if address is a contract
    function isContract(address _addr) private view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
