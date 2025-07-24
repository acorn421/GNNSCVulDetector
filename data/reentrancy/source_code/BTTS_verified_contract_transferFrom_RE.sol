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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism to notify recipient contracts about incoming tokens. The external call is placed after balance updates but before allowance reduction, creating a critical window for exploitation.
 * 
 * **How the vulnerability works across multiple transactions:**
 * 
 * 1. **Transaction 1 (Setup)**: Token holder approves a spender for X tokens using approve()
 * 2. **Transaction 2 (Initial exploit)**: Malicious contract calls transferFrom() with approved amount
 * 3. **During Transaction 2**: The callback to the malicious recipient contract is triggered
 * 4. **Reentrant call**: The malicious contract calls transferFrom() again with the same allowance (since it hasn't been reduced yet)
 * 5. **Transaction 3+ (Continued exploitation)**: Multiple reentrant calls can drain tokens exceeding the original allowance
 * 
 * **Why this requires multiple transactions:**
 * - The vulnerability depends on pre-existing approval state from a previous transaction
 * - Each reentrant call creates a new execution context that can be exploited
 * - The allowance state persists between the initial call and reentrant calls, enabling multiple withdrawals
 * - The exploit requires accumulated state changes across multiple function invocations
 * 
 * **Exploitation scenario:**
 * 1. Alice approves Bob for 100 tokens
 * 2. Bob (malicious contract) calls transferFrom(Alice, Bob, 100)
 * 3. During the callback, Bob calls transferFrom(Alice, Bob, 100) again
 * 4. Both calls succeed because allowance is only reduced after the callback
 * 5. Bob receives 200 tokens despite only being approved for 100
 * 
 * This creates a realistic stateful reentrancy vulnerability that requires multiple transactions and persistent state to exploit effectively.
 */
pragma solidity ^0.4.11;

contract BTTS {

    string public name = "BTTS";      //  token name
    string public symbol = "BTTS";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;  //balance of each address
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000000000000000000000; // token amount
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value)  validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value)  validAddress public returns (bool) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming tokens (potential reentrancy point)
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)  validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Util function to check if _addr is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
