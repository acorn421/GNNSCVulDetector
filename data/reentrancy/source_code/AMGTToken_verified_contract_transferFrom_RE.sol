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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added external call**: Inserted `_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)` after balance updates but before allowance decrement
 * 2. **Positioned strategically**: The external call occurs after `balanceOf` updates but before `allowance` state update, creating a reentrancy window
 * 3. **Realistic implementation**: Added as a "transfer notification" feature that appears legitimate but introduces vulnerability
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Alice approves MaliciousContract for 1000 tokens: `approve(maliciousContract, 1000)`
 * - State: `allowance[Alice][maliciousContract] = 1000`
 * 
 * **Transaction 2 (Initial Transfer)**:
 * - Bob calls `transferFrom(Alice, maliciousContract, 500)`
 * - Function executes: balances updated, external call to `maliciousContract.onTokenReceived()`
 * - **Critical**: `allowance[Alice][maliciousContract]` is still 1000 (not yet decremented)
 * 
 * **Transaction 2 (Reentrant Calls)**:
 * - Inside `onTokenReceived()`, MaliciousContract calls `transferFrom(Alice, maliciousContract, 500)` again
 * - Since allowance hasn't been decremented yet, the check passes
 * - This can be repeated multiple times in the same transaction
 * - Each reentrant call drains 500 more tokens from Alice
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **State Accumulation**: Requires prior `approve()` transaction to set allowance
 * 2. **Persistent State Window**: The vulnerability exploits the gap between balance updates and allowance updates across function calls
 * 3. **External Call Dependency**: Requires malicious contract deployment and setup before exploitation
 * 4. **Sequential Exploitation**: Each reentrant call builds on the state from previous calls within the same transaction sequence
 * 
 * **Exploitation Flow:**
 * 1. **Setup Phase** (Separate Transaction): Deploy malicious contract, get approval
 * 2. **Trigger Phase** (Main Transaction): Call transferFrom → External call → Reentrant transferFrom calls
 * 3. **State Persistence**: Each call uses the same allowance value before final decrement
 * 
 * The vulnerability is stateful because it depends on pre-existing allowance state from previous transactions and creates a window where this state can be repeatedly exploited before being updated.
 */
pragma solidity ^0.4.11;

contract AMGTToken {

    string public name = "AmazingTokenTest";      //  token name
    string public symbol = "AMGT";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000000000;
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

    function AMGTToken() public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about the transfer (vulnerable external call)
        if (isContract(_to)) {
            // External call before allowance update creates reentrancy window
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner public {
        stopped = true;
    }

    function start() isOwner public {
        stopped = false;
    }

    function setName(string _name) isOwner public {
        name = _name;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}