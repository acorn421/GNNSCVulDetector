/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to a burn observer contract. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Setup Phase**: Attacker deploys a malicious burn observer contract and gets it set as the burnObserver
 * 2. **Exploitation Phase**: The malicious observer can reenter the burn function during the onBurnInitiated() callback, before state is updated
 * 3. **State Persistence**: The vulnerability exploits the fact that balance checks happen before state updates, and the observer can manipulate this timing across multiple calls
 * 
 * **Multi-Transaction Exploitation Process:**
 * - Transaction 1: Attacker calls burn() with legitimate tokens
 * - During onBurnInitiated() callback: Attacker's observer contract calls burn() again reentrantly
 * - The reentrant call sees the old balance (before the first burn's state update)
 * - This allows burning more tokens than actually owned across multiple nested calls
 * - Each reentrant call can further call burn() before any state updates are finalized
 * 
 * **Why Multi-Transaction**: The vulnerability requires:
 * 1. Initial legitimate transaction to trigger the burn
 * 2. Reentrant calls during the external observer notification
 * 3. State manipulation that persists between the nested calls
 * 4. The exploit builds up across multiple function invocations within the call stack
 * 
 * The vulnerability is realistic because burn notifications to external systems are common in production token contracts, and the observer pattern is a legitimate design choice that introduces this attack vector.
 */
pragma solidity ^0.4.21;

library SafeMath {
    /**
    * @dev Multiplies two numbers, throws on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    /**
    * @dev Integer division of two numbers, truncating the quotient.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    /**
    * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    /**
    * @dev Adds two numbers, throws on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a && c >= b);
        return c;
    }
}

interface IBurnObserver {
    function onBurnInitiated(address burner, uint256 value, uint256 oldBalance) external;
    function onBurnCompleted(address burner, uint256 value, uint256 newBalance) external;
}

contract UPEXCoin {
    using SafeMath for uint256;

    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;

    mapping (address => mapping (address => uint256)) internal allowed;
    mapping(address => uint256) balances;

    uint256 totalSupply_;
    address public burnObserver;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Burn(address indexed burner, uint256 value);

    constructor() public {
        decimals = 18;
        totalSupply_ = 100 * 100000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balances[msg.sender] = totalSupply_;                // Give the creator all initial tokens
        name = "Upex Coin";                                   // Set the name for display purposes
        symbol = "UPEX";                               // Set the symbol for display purposes
    }

    /**
    * @dev total number of tokens in existence
    */
    function totalSupply() public view returns (uint256) {
        return totalSupply_;
    }

    /**
    * @dev transfer token for a specified address
    * @param _to The address to transfer to.
    * @param _value The amount to be transferred.
    */
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));
        require(_value > 0);
        require(_value <= balances[msg.sender]);

        // SafeMath.sub will throw if there is not enough balance.
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
    * @dev Gets the balance of the specified address.
    * @param _owner The address to query the the balance of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    /**
     * @dev Transfer tokens from one address to another
     * @param _from address The address which you want to send tokens from
     * @param _to address The address which you want to transfer to
     * @param _value uint256 the amount of tokens to be transferred
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));
        require(_value > 0);
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);

        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    /**
     * @dev Burns a specific amount of tokens.
     * @param _value The amount of token to be burned.
     */
    function burn(uint256 _value) public {
        require(_value <= balances[msg.sender]);
        // no need to require value <= totalSupply, since that would imply the
        // sender's balance is greater than the totalSupply, which *should* be an assertion failure

        address burner = msg.sender;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint256 oldBalance = balances[burner];
        
        // Notify external burn observer before updating state
        if (burnObserver != address(0)) {
            IBurnObserver(burnObserver).onBurnInitiated(burner, _value, oldBalance);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[burner] = balances[burner].sub(_value);
        totalSupply_ = totalSupply_.sub(_value);
        emit Burn(burner, _value);
        emit Transfer(burner, address(0), _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Post-burn notification that can trigger additional logic
        if (burnObserver != address(0)) {
            IBurnObserver(burnObserver).onBurnCompleted(burner, _value, balances[burner]);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    /**
     * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
     *
     * Beware that changing an allowance with this method brings the risk that someone may use both the old
     * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
     * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     * @param _spender The address which will spend the funds.
     * @param _value The amount of tokens to be spent.
     */
    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * @dev Function to check the amount of tokens that an owner allowed to a spender.
     * @param _owner address The address which owns the funds.
     * @param _spender address The address which will spend the funds.
     * @return A uint256 specifying the amount of tokens still available for the spender.
     */
    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
    }
}
