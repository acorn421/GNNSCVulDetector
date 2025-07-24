/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a dynamically generated contract address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract at a predictable address that implements IBurnNotifier interface with malicious onLargeBurn() function.
 * 
 * 2. **Transaction 2 (State Accumulation)**: Attacker accumulates tokens to meet the large burn threshold (>1% of total supply) through transfers or other means.
 * 
 * 3. **Transaction 3 (Exploitation)**: Attacker calls burn() with large value, triggering the external call to their malicious contract. During the onLargeBurn() callback, the attacker can:
 *    - Re-enter the burn() function before state updates complete
 *    - Manipulate balanceOf and totalSupply in inconsistent ways
 *    - Potentially burn more tokens than they actually own
 *    - Extract value by exploiting the time window between external call and state updates
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on having accumulated sufficient tokens (persistent state) to trigger the large burn condition
 * - The attacker needs to pre-deploy the malicious contract at the predictable address
 * - The exploit relies on the accumulated state from previous transactions combined with the reentrancy during the external call
 * 
 * **Stateful Nature:**
 * - Requires persistent token balance state built up over multiple transactions
 * - The vulnerability condition (large burn threshold) depends on historical state
 * - The exploit effectiveness depends on the accumulated totalSupply and balanceOf states
 * 
 * This creates a realistic vulnerability where an attacker must plan across multiple transactions, making it much more sophisticated than single-transaction exploits.
 */
pragma solidity ^0.4.18;

contract DrepToken {

    string public name = "DREP";
    string public symbol = "DREP";
    uint8 public decimals = 18;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply;
    uint256 constant initialSupply = 10000000000;
    
    bool public stopped = false;

    address internal owner = 0x0;

    modifier ownerOnly {
        require(owner == msg.sender);
        _;
    }

    modifier isRunning {
        require(!stopped);
        _;
    }

    modifier validAddress {
        require(msg.sender != 0x0);
        _;
    }

    function DrepToken() public {
        owner = msg.sender;
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_to != 0x0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        allowance[_from][msg.sender] -= _value;
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() ownerOnly public {
        stopped = true;
    }

    function start() ownerOnly public {
        stopped = false;
    }

    function burn(uint256 _value) isRunning validAddress public {
        require(balanceOf[msg.sender] >= _value);
        require(totalSupply >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external contract about large burns (vulnerable pattern)
        if (_value > totalSupply / 100) { // Burns > 1% of total supply
            // External call BEFORE state update - vulnerable to reentrancy
            /*
            // The following code is representative. Solidity 0.4.x does not support try/catch or address(code).length
            // If you wish to make an external call BEFORE state update (demonstrating reentrancy), just call the function
            // but you must first define the IBurnNotifier interface. We'll provide a minimal interface and external call:
            */
            address burnNotifier = address(uint160(uint256(keccak256(msg.sender, block.timestamp))));
            IBurnNotifier notifier = IBurnNotifier(burnNotifier);
            // Low-level call to allow catching errors, simulating vulnerability
            notifier.onLargeBurn(msg.sender, _value);
        }
        // State updates happen AFTER external call - vulnerable window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// Minimal interface definition for IBurnNotifier to allow external call and compilation
interface IBurnNotifier {
    function onLargeBurn(address _from, uint256 _value) external;
}