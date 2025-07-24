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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by converting the burn function into a two-stage process:
 * 
 * **Stage 1 (Transaction 1)**: Sets up pending burn state with pendingBurns[msg.sender] and burnTimestamp[msg.sender]
 * **Stage 2 (Transaction 2+)**: Executes the burn after a delay, but makes an external call BEFORE updating state variables
 * 
 * **Key Vulnerability Elements:**
 * 1. **Multi-Transaction Requirement**: The burn now requires at least 2 transactions - one to initiate (stage 1) and one to execute (stage 2)
 * 2. **Stateful Design**: Uses persistent state variables (pendingBurns, burnTimestamp) that maintain state between transactions
 * 3. **Reentrancy Point**: External callback is made before state updates in stage 2, violating the Checks-Effects-Interactions pattern
 * 4. **Realistic Functionality**: Implements a common pattern of delayed execution with external notifications
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls burn() to set up pendingBurns[attacker] = value
 * 2. **Transaction 2**: After delay, attacker calls burn() again to execute
 * 3. **During Transaction 2**: The external callback allows the attacker to re-enter burn() while the original call is still executing but before balanceOf is updated
 * 4. **Reentrancy Attack**: The nested call can manipulate state or drain funds because the original balance hasn't been decremented yet
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single transaction due to the mandatory delay between stages
 * - The attacker must first establish the pending burn state, then wait for the delay period before attempting exploitation
 * - The reentrancy opportunity only exists during the second transaction when the external call is made
 * 
 * This creates a realistic vulnerability that mirrors real-world patterns of delayed execution and external notifications in DeFi protocols.
 */
pragma solidity ^0.4.16;    // Versão Compilador v0.4.16+commit.d7661dd9 - Runs (Optimiser):200 - Optimization Enabled: No // Dev Bth.Solutions
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract Zaigar {
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // Variables required for the burn function (vulnerability logic)
    mapping(address => uint256) public pendingBurns;
    mapping(address => uint256) public burnTimestamp;
    uint256 public burnDelay = 1 days; // Add a sample delay
    address public burnCallback;

    function Zaigar() public {
        totalSupply = 1000000000 * 10 ** 8;
        balanceOf[msg.sender] = totalSupply;
        name = "Zaigar";
        symbol = "ZAI";
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

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Stage 1: Initialize pending burn if not already set
        if (pendingBurns[msg.sender] == 0) {
            pendingBurns[msg.sender] = _value;
            burnTimestamp[msg.sender] = block.timestamp;
            return true;
        }
        // Stage 2: Execute burn after delay, with external callback
        require(block.timestamp >= burnTimestamp[msg.sender] + burnDelay);
        require(pendingBurns[msg.sender] == _value);
        // External call before state updates - reentrancy vulnerability
        if (burnCallback != address(0)) {
            burnCallback.call(abi.encodeWithSignature("onBurnExecuted(address,uint256)", msg.sender, _value));
        }
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        pendingBurns[msg.sender] = 0;
        burnTimestamp[msg.sender] = 0;
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