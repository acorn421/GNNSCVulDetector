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
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification hook after balance updates but before allowance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call(abi.encodeWithSignature("tokensReceived(address,address,uint256)", _from, _to, _value))`
 * 2. Positioned the call after balance updates but before allowance reduction
 * 3. Used low-level call that allows reentrancy without reverting on failure
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Attacker creates malicious contract and obtains allowance from victim
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls transferFrom to malicious contract, which triggers the notification hook
 * 3. **Transaction 3+ (Reentrancy Chain)**: The malicious contract's tokensReceived function calls transferFrom again, creating a reentrancy loop where:
 *    - Balances are updated each time (tokens transferred)
 *    - Allowance is only reduced after the external call
 *    - Multiple transfers can occur before allowance is properly decremented
 * 
 * **Why Multiple Transactions Are Required:**
 * - Initial setup requires establishing allowances and contract deployment
 * - Each reentrancy call creates new state that persists between transactions
 * - The vulnerability accumulates effects across multiple calls rather than being atomic
 * - Attacker needs to build up state and execute the attack sequence over multiple blocks
 * 
 * **Stateful Nature:**
 * - Balance changes persist between transactions
 * - Allowance decrements are delayed, creating exploitable state inconsistencies
 * - Each successful reentrancy call changes the contract state for subsequent calls
 * - The attack builds upon previous state changes rather than being self-contained
 * 
 * This creates a realistic vulnerability where an attacker can potentially drain more tokens than their allowance should permit by exploiting the timing between balance updates and allowance reductions across multiple transaction calls.
 */
pragma solidity ^0.4.21;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
    address public owner;


    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor () public {
        owner = msg.sender;
    }


    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }


    /**
     * @dev Allows the current owner to transfer control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

/**
 *  @title Contract for CoinMetro Token
 *  Dec 2017, Anton Corbijn (CoinMetro)
 */
contract CoinMetroToken is Ownable {
    using SafeMath for uint;

    string public constant name = "CoinMetro Token";
    string public constant symbol = "XCM";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    bool public mintingFinished = false;

    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    event NewToken(address _token);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Burned(address burner, uint burnedAmount);
    event MintFinished();

    modifier canMint() {
        require(!mintingFinished, "Minting was already finished");
        _;
    }

    constructor () public {
        emit NewToken(address(this));
    }

    /**
     * @dev Function to mint tokens
     * @param _to The address that will receive the minted tokens.
     * @param _amount The amount of tokens to mint.
     * @return A boolean that indicates if the operation was successful.
     */
    function mint(address _to, uint256 _amount) public onlyOwner canMint returns (bool) {
        totalSupply = totalSupply.add(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(address(0), _to, _amount);
        return true;
    }

    // Burn tokens from an address
    function burn(uint burnAmount) public {
        address burner = msg.sender;
        balances[burner] = balances[burner].sub(burnAmount);
        totalSupply = totalSupply.sub(burnAmount);
        emit Burned(burner, burnAmount);
    }

    /**
     * @dev Function to stop minting new tokens.
     * @return True if the operation was successful.
     */
    function finishMinting() public onlyOwner returns (bool) {
        mintingFinished = true;
        emit MintFinished();
        return true;
    }

    /**
    * @dev transfer token for a specified address
    * @param _to The address to transfer to.
    * @param _value The amount to be transferred.
    */
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0), "Address should not be zero");
        require(_value <= balances[msg.sender], "Insufficient balance");

        // SafeMath.sub will throw if there is not enough balance.
        balances[msg.sender] = balances[msg.sender] - _value;
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * @dev Transfer tokens from one address to another
     * @param _from address The address which you want to send tokens from
     * @param _to address The address which you want to transfer to
     * @param _value uint256 the amount of tokens to be transferred
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_to != address(0), "Address should not be zero");
        require(_value <= balances[_from], "Insufficient Balance");
        require(_value <= allowed[_from][msg.sender], "Insufficient Allowance");

        balances[_from] = balances[_from] - _value;
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        uint32 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            _to.call(abi.encodeWithSignature("tokensReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution even if notification fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = allowed[_from][msg.sender] - _value;
        emit Transfer(_from, _to, _value);
        return true;
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
    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    /**
     * approve should be called when allowed[_spender] == 0. To increment
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * From MonolithDAO Token.sol
     */
    function increaseApproval (address _spender, uint _addedValue) public returns (bool success) {
        allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function decreaseApproval (address _spender, uint _subtractedValue) public returns (bool success) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
        }
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
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
}