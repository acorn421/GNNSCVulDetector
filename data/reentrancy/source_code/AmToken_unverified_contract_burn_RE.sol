/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the caller's contract before state updates are complete. The vulnerability is exploitable through multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `msg.sender.call(abi.encodeWithSignature("onBeforeBurn(uint256)", _value))` before state updates
 * 2. Placed the external call after the balance check but before state modifications
 * 3. Used low-level call to avoid compilation issues with unknown interface
 * 4. Added contract existence check to make the call appear more legitimate
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burn()` with amount X
 *    - Balance check passes (require statement)
 *    - External call triggers attacker's `onBeforeBurn()` callback
 *    - In callback, attacker calls `burn()` again (Transaction 2)
 *    - Original transaction completes, updating state
 * 
 * 2. **Transaction 2**: Reentrant call to `burn()` with amount Y
 *    - Balance check still passes (state not yet updated from Transaction 1)
 *    - Another external call can trigger more reentrancy
 *    - State gets updated again
 * 
 * 3. **Accumulated Effect**: Multiple overlapping burn operations can execute with stale balance checks, allowing burning more tokens than actually owned
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * - The vulnerability exploits the window between the balance check and state update
 * - Each reentrant call creates a new transaction context with access to stale state
 * - The accumulated effect of multiple overlapping burns can exceed the user's actual balance
 * - Single-transaction reentrancy would be limited by gas costs, but multi-transaction reentrancy can compound the effect
 * - The persistent state changes (balanceOf and totalSupply) accumulate across multiple transaction calls
 * 
 * **Realistic Integration:**
 * - The burn notification hook is a common pattern in DeFi protocols
 * - External calls to notify about token burns are realistic for governance or tracking purposes
 * - The vulnerability appears as a legitimate feature but creates a security flaw through improper ordering
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
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0);
        uint256 c = a / b;
        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;
        return c;
    }
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
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Replace msg.sender.code.length > 0 with isContract(msg.sender)
        if (isContract(msg.sender)) {
            (bool success, ) = msg.sender.call(abi.encodeWithSignature("onBeforeBurn(uint256)", _value));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    // Helper function to replicate code.length in Solidity <0.8.0
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
