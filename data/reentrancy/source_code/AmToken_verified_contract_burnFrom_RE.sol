/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding an external callback to the token holder (_from) before state updates. This creates a classic violation of the checks-effects-interactions pattern where external calls occur before critical state changes.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_from).receiveApproval()` after initial checks but before state modifications
 * 2. Added condition to only call external contract if `_from != msg.sender` (realistic burn notification scenario)
 * 3. Added check for contract code existence (`_from.code.length > 0`) to avoid calls to EOAs
 * 4. Used existing `tokenRecipient` interface for realistic callback integration
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker creates malicious contract implementing `tokenRecipient`
 * - Attacker approves themselves to burn tokens from their malicious contract
 * - Attacker's contract holds tokens and has allowance set
 * 
 * **Transaction 2 - Reentrancy Attack:**
 * - External user calls `burnFrom(attackerContract, amount)`
 * - Function performs initial checks (balance and allowance sufficient)
 * - External call triggers `attackerContract.receiveApproval()`
 * - **During callback**: Attacker's contract calls `approve()` to increase allowance or `transfer()` to move tokens
 * - **State manipulation**: Attacker can modify balances/allowances before original burn completes
 * - Original function continues with potentially inconsistent state
 * 
 * **Transaction 3+ - Repeated Exploitation:**
 * - Attacker can repeat the process with manipulated state
 * - Each transaction builds on previous state changes
 * - Multiple users can unknowingly participate in the attack sequence
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Persistence**: Modified allowances and balances persist between transactions
 * 2. **Accumulated Effect**: Each exploitation round can manipulate state for subsequent attacks
 * 3. **Cross-User Interaction**: Different users calling burnFrom can trigger callbacks to the same malicious contract
 * 4. **Time-Based Exploitation**: Attacker can wait for optimal conditions between transactions
 * 
 * This vulnerability requires multiple transactions because the state changes (allowances, balances) must persist and accumulate across different function calls to be effectively exploited. A single transaction cannot achieve the same level of state manipulation due to the atomic nature of transaction execution.
 */
pragma solidity ^0.4.24;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {
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
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify token holder before burning (vulnerable external call)
        if(_from != msg.sender && isContract(_from)) {
            tokenRecipient(_from).receiveApproval(msg.sender, _value, address(this), "burn_notification");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = balanceOf[_from].sub(_value);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(_from, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
