/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordering State Updates**: The allowance is now updated AFTER the transfer and external call, creating a window for reentrancy.
 * 
 * 2. **External Call Introduction**: Added a callback to the recipient contract using the existing `tokenRecipient` interface, which allows the recipient to execute arbitrary code before the allowance is updated.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls `transferFrom`, triggers the callback, and can re-enter `transferFrom` multiple times using the same allowance (since it hasn't been updated yet)
 *    - **Transaction 2+**: Attacker continues exploiting the persistent allowance state across multiple blocks/transactions
 *    - Each transaction can exploit the accumulated allowance state that persists between calls
 * 
 * 4. **State Persistence**: The `allowance` mapping persists between transactions, allowing the attacker to exploit the same allowance amount across multiple separate transactions before it gets properly decremented.
 * 
 * 5. **Realistic Vulnerability**: This follows a common pattern where developers add callback functionality without considering reentrancy implications, moving state updates to after external calls.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - Alice approves Bob for 100 tokens
 * - Bob calls `transferFrom` in Transaction 1, gets callback, re-enters multiple times draining 300 tokens
 * - In Transaction 2, Bob can still exploit any remaining allowance state
 * - The vulnerability requires multiple transactions because the allowance state persists and can be exploited across different blockchain transactions
 * 
 * **Why Multi-Transaction**: The vulnerability is multi-transaction because:
 * 1. The allowance state persists between transactions
 * 2. An attacker can exploit the same allowance across multiple separate blockchain transactions
 * 3. The accumulated state changes (token transfers) build up across multiple transactions
 * 4. Each transaction can further exploit the persistent allowance state until it's finally updated
 */
pragma solidity ^0.4.24;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {
    /**
    * @dev Multiplies two numbers, reverts on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
    * @dev Integer division of two numbers truncating the quotient, reverts on division by zero.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0); // Solidity only automatically asserts when dividing by 0
        uint256 c = a / b;

        return c;
    }

    /**
    * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    /**
    * @dev Adds two numbers, reverts on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0);
        return a % b;
    }
}

contract AmToken {
    using SafeMath for uint256;
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor (
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        require(_to != address(0));
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to].add(_value) >= balanceOf[_to]);
        uint256 previousBalances = balanceOf[_from].add(balanceOf[_to]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from].add(balanceOf[_to]) == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        _transfer(_from, _to, _value);

        if (isContract(_to)) {
            // Perform external call to recipient -- maintain vulnerability
            tokenRecipient(_to).receiveApproval(_from, _value, address(this), "");
        }

        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // Helper (not marked as view to stay compatible w/ ^0.4.24 and avoid interface issues)
    function isContract(address _addr) internal constant returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        require(_spender != address(0));
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(_from, _value);
        return true;
    }
}
