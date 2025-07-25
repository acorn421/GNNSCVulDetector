/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer_admin
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to user-controlled contracts after state updates but before completion. The vulnerability allows attackers to manipulate the multi-signature approval process across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call After State Update**: Added `_to.call(bytes4(keccak256("onApprovalUpdate(address,uint256,uint256)")), msg.sender, _curr_as, _value)` after updating `admin_tran_as[_to][_value]` and `admin_tran_addrs[_to][_value]`. This violates the Checks-Effects-Interactions pattern.
 * 
 * 2. **Added External Call Before Final Transfer**: Added `_to.call(bytes4(keccak256("onThresholdReached(address,uint256)")), msg.sender, _value)` before calling `transfer_admin_f()` when the threshold is reached.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker calls `transfer_admin()` with a malicious contract as `_to`
 * - State gets updated: `admin_tran_as[attacker_contract][value] = approval_amount`
 * - External call to `attacker_contract.onApprovalUpdate()` is made
 * - Attacker contract can now see the updated approval state
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transfer_admin()` again from a different admin address
 * - When the threshold is reached, the external call to `onThresholdReached()` triggers
 * - The attacker contract can now re-enter `transfer_admin()` with the same or different parameters
 * - Since state was already updated, the attacker can manipulate the approval process
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability exploits the fact that approval state (`admin_tran_as`, `admin_tran_addrs`) accumulates across multiple transactions until the threshold is reached.
 * 
 * 2. **Cross-Transaction State Manipulation**: The attacker needs multiple transactions to:
 *    - First, build up approval state legitimately
 *    - Then, exploit the external call when threshold conditions are met
 *    - Manipulate the approval process during reentrancy
 * 
 * 3. **Threshold-Based Exploitation**: The external call only happens when specific conditions are met (`_curr_as < admin_needa` initially, then `_curr_as >= admin_needa`), requiring multiple calls to reach the vulnerable state.
 * 
 * 4. **Persistent State Corruption**: The attacker can corrupt the approval tracking across multiple transactions, potentially approving unauthorized transfers or manipulating the multi-signature mechanism.
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions to exploit, as the attacker must first accumulate legitimate approvals before being able to exploit the external call when the threshold is reached.
 */
pragma solidity ^0.4.25;


/** https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/math/SafeMath.sol
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {
    /**
    * @dev Multiplies two unsigned integers, reverts on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
    * @dev Integer division of two unsigned integers truncating the quotient, reverts on division by zero.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
    * @dev Subtracts two unsigned integers, reverts on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    /**
    * @dev Adds two unsigned integers, reverts on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }
}

contract THB {
    using SafeMath for uint256;

    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    address owner;
    address[] admin_addrs;
    uint256[] admin_as;
    uint256 admin_needa;
    mapping(address => mapping(uint256 => uint256)) admin_tran_as;
    mapping(address => mapping(uint256 => address[])) admin_tran_addrs;

    mapping(address => uint256)  balances;
    mapping(address => mapping(address => uint256)) _allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event PreTransfer(address _admin, uint256 _lastas, address indexed _to, uint256 _value);

    constructor (uint256 _initialSupply, string _name, string _symbol,
        address[] _admin_addrs, uint256[] _admin_as, uint256 _admin_needa) public {
        balances[msg.sender] = _initialSupply;
        owner = msg.sender;
        totalSupply = _initialSupply;
        name = _name;
        symbol = _symbol;
        decimals = 18;
        require(_admin_addrs.length > 0 && _admin_addrs.length == _admin_as.length);
        require(_admin_needa >= 1);
        for (uint i = 0; i < _admin_addrs.length; i++) {
            require(_admin_addrs[i] != address(0));
        }
        for (i = 0; i < _admin_as.length; i++) {
            require(_admin_as[i] >= 1);
        }
        admin_addrs = _admin_addrs;
        admin_as = _admin_as;
        admin_needa = _admin_needa;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return _allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(msg.sender != owner);
        require(_value > 0);
        require(balances[msg.sender] >= _value);
        require(balances[_to] + _value >= balances[_to]);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transfer_admin(address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(_to != owner);
        require(_value > 0);

        uint256 _msgsendas = 0;
        for (uint i = 0; i < admin_addrs.length; i++) {
            if (admin_addrs[i] == msg.sender) {
                _msgsendas = admin_as[i];
                break;
            }
        }
        require(_msgsendas > 0);

        for (i = 0; i < admin_tran_addrs[_to][_value].length; i++) {
            require(admin_tran_addrs[_to][_value][i] != msg.sender);
        }

        uint256 _curr_as = admin_tran_as[_to][_value];

        if (_curr_as < admin_needa) {
            _curr_as = _curr_as.add(_msgsendas);
            if (_curr_as < admin_needa) {
                admin_tran_as[_to][_value] = _curr_as;
                admin_tran_addrs[_to][_value].push(msg.sender);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // External call to notify admin about approval progress - VULNERABILITY INJECTION
                if (_to.call(bytes4(keccak256("onApprovalUpdate(address,uint256,uint256)")), msg.sender, _curr_as, _value)) {
                    // Call succeeded - state was already updated above
                }
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                emit PreTransfer(msg.sender, _curr_as, _to, _value);
                return true;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // External call to notify about threshold reached - VULNERABILITY INJECTION
            if (_to.call(bytes4(keccak256("onThresholdReached(address,uint256)")), msg.sender, _value)) {
                // Call succeeded - about to execute transfer
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return transfer_admin_f(_to, _value);
        }
        // error
        require(false);
    }

    function transfer_admin_f(address _to, uint256 _value) internal returns (bool success) {
        require(balances[owner] >= _value);
        require(balances[_to] + _value >= balances[_to]);
        admin_tran_as[_to][_value] = 0;
        admin_tran_addrs[_to][_value] = new address[](0);
        balances[owner] = balances[owner].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(owner, _to, _value);
        return true;
    }

    /** https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/token/ERC20/ERC20.sol#L62
     * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
     * Beware that changing an allowance with this method brings the risk that someone may use both the old
     * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
     * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     */
    function approve(address spender, uint256 value) public returns (bool) {
        require(spender != address(0));

        _allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(_from != owner);
        require(_value > 0);
        uint256 _allow = _allowed[_from][msg.sender];
        require(_value <= _allow);
        require(balances[_from] >= _value);
        require(balances[_to] + _value >= balances[_to]);

        balances[_from] = balances[_from].sub(_value);
        _allowed[_from][msg.sender] = _allow.sub(_value);
        balances[_to] = balances[_to].add(_value);

        emit Transfer(_from, _to, _value);
        return true;
    }

    /** https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/token/ERC20/ERC20.sol#L94
     * @dev Increase the amount of tokens that an owner allowed to a spender.
     * approve should be called when allowed_[_spender] == 0. To increment
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * From MonolithDAO Token.sol
     * Emits an Approval event.
     * @param spender The address which will spend the funds.
     * @param addedValue The amount of tokens to increase the allowance by.
     */
    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        require(spender != address(0));

        _allowed[msg.sender][spender] = _allowed[msg.sender][spender].add(addedValue);
        emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
        return true;
    }

    /** https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/token/ERC20/ERC20.sol#L122
     * @dev Decrease the amount of tokens that an owner allowed to a spender.
     * approve should be called when allowed_[_spender] == 0. To decrement
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * From MonolithDAO Token.sol
     * Emits an Approval event.
     * @param spender The address which will spend the funds.
     * @param subtractedValue The amount of tokens to decrease the allowance by.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
        require(spender != address(0));

        _allowed[msg.sender][spender] = _allowed[msg.sender][spender].sub(subtractedValue);
        emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
        return true;
    }


    function burn(uint256 _value) public returns (bool success) {
        require(_value > 0);
        require(msg.sender != owner);
        require(balances[msg.sender] >= _value);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender, _value);
        return true;
    }

    function withdrawEther(uint256 amount) public {
        require(msg.sender == owner);
        owner.transfer(amount);
    }

    function() public payable {
    }
}