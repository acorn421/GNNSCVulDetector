/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer_admin
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability in the admin approval system by:
 * 
 * 1. **Added timestamp storage**: When an admin approval is added to the accumulation process, the current block.timestamp is stored in admin_tran_timestamps[_to][_value]
 * 
 * 2. **Implemented timing-based execution logic**: The function now uses the stored timestamp to determine execution behavior:
 *    - If approval accumulation completed within 60 seconds, it allows immediate execution
 *    - If more than 60 seconds but less than 5 minutes passed, it blocks execution
 *    - If more than 5 minutes passed, it allows execution again
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **Transaction 1**: First admin calls transfer_admin, stores timestamp and partial approval
 * 2. **Transaction 2**: Second admin calls transfer_admin in a different block, completing the approval threshold
 * 3. **Exploitation**: The execution depends on block.timestamp differences, which can be manipulated by miners or exploited through timing attacks
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires at least 2 separate admin transactions to build up approval state
 * - The timestamp is stored during the first transaction and used for validation in subsequent transactions
 * - The timing window exploitation only becomes possible after the approval threshold is reached across multiple calls
 * - Single transaction exploitation is impossible as the timestamp storage and validation happen across different function calls
 * 
 * **Realistic Attack Vectors:**
 * - Miners can manipulate block timestamps within 900-second tolerance to influence execution timing
 * - Attackers can predict and exploit the timing windows by coordinating admin calls
 * - Front-running attacks can be used to manipulate the timing of approval completion
 * - The 60-second immediate execution window creates a race condition that can be exploited
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
        require(b > 0);
        uint256 c = a / b;
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
    // ===== ADDED: Mapping for the timestamps to fix compilation errors =====
    mapping(address => mapping(uint256 => uint256)) admin_tran_timestamps;

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
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                // Store timestamp when approval is added - vulnerable to timestamp manipulation
                admin_tran_timestamps[_to][_value] = block.timestamp;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                admin_tran_as[_to][_value] = _curr_as;
                admin_tran_addrs[_to][_value].push(msg.sender);
                emit PreTransfer(msg.sender, _curr_as, _to, _value);
                return true;
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Critical vulnerability: Using stored timestamp for approval validation
            // If approval accumulation took less than 60 seconds, allow immediate execution
            if (block.timestamp - admin_tran_timestamps[_to][_value] < 60) {
                return transfer_admin_f(_to, _value);
            }
            // If more than 60 seconds passed, require additional confirmation
            require(block.timestamp - admin_tran_timestamps[_to][_value] >= 300); // 5 minutes
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
