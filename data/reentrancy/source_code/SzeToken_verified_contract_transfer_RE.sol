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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE state updates. This creates a classic reentrancy vulnerability with the following exploitation pattern:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived` callback
 * 2. **Transaction 2 (Initial Transfer)**: Attacker calls `transfer()` to send tokens to their malicious contract
 * 3. **Reentrancy Window**: The external call to `onTokenReceived` executes BEFORE state is updated
 * 4. **Transaction 3+ (Exploitation)**: During the callback, attacker can call `transfer()` again with the same tokens (since balanceOf hasn't been updated yet)
 * 5. **State Accumulation**: Each reentrant call transfers tokens before the original state update completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The initial setup requires deploying the malicious contract (Transaction 1)
 * - The exploitation requires the original transfer call (Transaction 2) 
 * - The reentrancy callback triggers additional transfers (Transaction 3+)
 * - Each call builds upon the previous state, allowing multiple transfers of the same tokens
 * - The vulnerability accumulates effect across multiple function calls within the same transaction tree
 * 
 * **Stateful Nature:**
 * - The vulnerability depends on the persistent state of balanceOf mappings
 * - Each reentrant call can transfer tokens before the previous call's state update
 * - The malicious contract's state persists between calls, enabling sophisticated exploitation
 * - The token balances are persistent state that gets manipulated across the call chain
 * 
 * This creates a realistic production-like vulnerability where external calls to recipient contracts (common in modern token standards) are made before state updates, violating the checks-effects-interactions pattern.
 */
pragma solidity ^0.4.11;

contract SzeToken {

    string public name = "Szechuan Sauce Coin";      //  token name
    string public symbol = "SZE";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 100000000000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    // Changed constructor syntax for Solidity 0.4.11
    function SzeToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract (adds external call vulnerability)
        if (isContract(_to)) {
            // External call BEFORE state update - creates reentrancy window
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call result
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    // Helper to determine if address is a contract in Solidity <0.5.0
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
