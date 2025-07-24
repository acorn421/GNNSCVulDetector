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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a reentrancy window where malicious contracts can exploit the inconsistent state across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * 1. **Transaction 1 (Initial Setup)**: 
 *    - Attacker deploys malicious contract with `tokenFallback` function
 *    - Attacker calls `transfer()` to send tokens to their malicious contract
 *    - The external call triggers `tokenFallback` in the malicious contract
 *    - At this point, `balanceOf[msg.sender]` still contains the original balance (not yet decremented)
 *    - The malicious contract can initiate additional transfers while the first transaction is still executing
 * 
 * 2. **Transaction 2+ (Reentrancy Chain)**:
 *    - The malicious `tokenFallback` function calls `transfer()` again
 *    - Each reentrant call sees the unchanged `balanceOf[msg.sender]` balance
 *    - Multiple transfers can be executed using the same balance
 *    - State accumulates across these calls, allowing drainage of more tokens than the sender actually owns
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The vulnerability exploits the fact that `balanceOf` state persists between function calls and is only updated after the external call
 * 2. **Accumulated Effect**: Each reentrant call can transfer the same amount again, with the total drain being the sum of all reentrant calls
 * 3. **Cross-Transaction Dependencies**: The exploit requires the external call to trigger subsequent calls that depend on the unchanged state from the initial transaction
 * 4. **Progressive Depletion**: The attack becomes more effective with each additional reentrant call, making it inherently multi-transaction
 * 
 * This vulnerability is realistic as many token contracts implement callback mechanisms for contract recipients, but the placement of the external call before state updates creates a classic reentrancy vulnerability that requires multiple function invocations to fully exploit.
 */
/**
 *Submitted for verification at Etherscan.io on 2017-08-28
*/

pragma solidity ^0.4.11;

contract BatToken {

    string public name = "Basic Attention Token";      //  token name
    string public symbol = "BAT";           //  token symbol
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

    // Changed to constructor declaration
    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Cast address to contract to access .call
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if(codeLength > 0) {
            // Attempt to call tokenFallback if recipient is a contract
            bool callSuccess = _to.call(bytes4(keccak256("tokenFallback(address,uint256)")), msg.sender, _value);
            // Continue regardless of call success for compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}