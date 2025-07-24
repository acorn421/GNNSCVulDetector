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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract: `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value))`
 * 2. Placed this call BEFORE state updates (violates Checks-Effects-Interactions pattern)
 * 3. Added contract existence check: `if (_to.code.length > 0)`
 * 4. Added require statement for call success to make it realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `approve()` to give allowance to a malicious contract
 * 2. **Transaction 2**: Malicious contract calls `transferFrom()` with itself as `_to`
 * 3. **During Transaction 2**: The `onTokenReceived` callback is triggered BEFORE state updates
 * 4. **Within Callback**: Malicious contract calls `transferFrom()` again with the same allowance
 * 5. **Transaction 3+**: Process repeats across multiple transactions, draining funds
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires pre-existing allowance state from previous transactions
 * - Each reentrancy call depletes allowance but can be reset through separate approve() calls
 * - The attacker can strategically time multiple transferFrom calls across different blocks
 * - State accumulation (allowance manipulation) enables repeated exploitation
 * 
 * **State Persistence Requirements:**
 * - Allowance state persists between transactions and enables the vulnerability
 * - Balance states are modified incrementally across multiple calls
 * - The malicious contract can maintain its own state to coordinate attacks across transactions
 * 
 * This creates a realistic reentrancy pattern where the vulnerability requires careful orchestration across multiple transactions rather than simple single-transaction exploitation.
 */
pragma solidity ^0.4.11;

contract MycoinToken {

    string public name = "Mycoin";      //  token name
    string public symbol = "MYC";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2100000000000000;
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

    function MycoinToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient contract before state updates (vulnerability injection)
        if (isContract(_to)) {
            // Note: Type is just 'address' in 0.4.11, no call success check possible
            if(!_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value)) {
                revert();
            }
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}