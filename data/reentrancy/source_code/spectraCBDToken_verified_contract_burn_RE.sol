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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burnTracker contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnTracker(burnTracker).onBurn(destroyer, _amount)` after the balance check but before state updates
 * 2. This violates the Checks-Effects-Interactions pattern by placing the external call between checks and effects
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Destroyer calls burn(100) with balance of 100 tokens
 *    - Balance check passes (100 >= 100)
 *    - External call to burnTracker.onBurn() is made
 *    - Malicious burnTracker contract re-enters and calls burn(50) during the callback
 *    - Inner burn(50) execution completes, reducing balance to 50 and totalSupply by 50
 *    - Original burn(100) resumes and reduces balance by another 100 (to -50, underflow) and totalSupply by 100
 * 
 * 2. **Transaction 2**: Destroyer calls burn(X) again
 *    - Due to the state manipulation from Transaction 1, the contract's state is corrupted
 *    - The destroyer can burn more tokens than they should have, or the underflow allows burning from other users' balances
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the destroyer to initiate multiple burn operations
 * - Each burn operation's external call can manipulate the contract state that affects subsequent burns
 * - The reentrancy attack accumulates state corruption across multiple transactions
 * - A single transaction alone cannot fully exploit the vulnerability - it requires the persistent state changes from previous transactions to enable further exploitation
 * 
 * **State Persistence:**
 * - balances[destroyer] and totalSupply modifications persist between transactions
 * - The corrupted state from one burn operation enables more severe exploitation in subsequent burns
 * - The vulnerability compounds over multiple transactions, making it a true multi-transaction attack vector
 */
pragma solidity ^0.4.18;

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
  constructor() public {
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
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}
/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
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

// Interface for the external burn tracker
interface IBurnTracker {
    function onBurn(address destroyer, uint256 amount) external;
}

contract spectraCBDToken is Ownable {
  string public constant name = "spectraCBDToken";
  string public constant symbol = "SCBD";
  uint8 public constant decimals = 18;

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);
  event Mint(address indexed to, uint256 amount);
  event MintingFinished();
  event Burn(uint256 amount);

  uint256 public totalSupply;


  //==================================================================================
  // Zeppelin BasicToken (plus modifier to not allow transfers during minting period):
  //==================================================================================

  using SafeMath for uint256;

  mapping(address => uint256) public balances;

  /**
  * @dev transfer token for a specified address
  * @param _to The address to transfer to.
  * @param _value The amount to be transferred.
  */
  function transfer(address _to, uint256 _value) public whenMintingFinished returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

    // SafeMath.sub will throw if there is not enough balance.
    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    Transfer(msg.sender, _to, _value);
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


  //=====================================================================================
  // Zeppelin StandardToken (plus modifier to not allow transfers during minting period):
  //=====================================================================================
  mapping (address => mapping (address => uint256)) public allowed;


  /**
   * @dev Transfer tokens from one address to another
   * @param _from address The address which you want to send tokens from
   * @param _to address The address which you want to transfer to
   * @param _value uint256 the amout of tokens to be transfered
   */
  function transferFrom(address _from, address _to, uint256 _value) public whenMintingFinished returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    Transfer(_from, _to, _value);
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
  function approve(address _spender, uint256 _value) public whenMintingFinished returns (bool) {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
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

  /**
   * approve should be called when allowed[_spender] == 0. To increment
   * allowed value is better to use this function to avoid 2 calls (and wait until
   * the first transaction is mined)
   * From MonolithDAO Token.sol
   */
  function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
    allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
    Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

  function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
    uint oldValue = allowed[msg.sender][_spender];
    if (_subtractedValue > oldValue) {
      allowed[msg.sender][_spender] = 0;
    } else {
      allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
    }
    Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }


  //=====================================================================================
  // Minting:
  //=====================================================================================

  bool public mintingFinished = false;
  address public destroyer;
  address public minter;
  address public burnTracker;

  modifier canMint() {
    require(!mintingFinished);
    _;
  }

  modifier whenMintingFinished() {
    require(mintingFinished);
    _;
  }

  modifier onlyMinter() {
    require(msg.sender == minter);
    _;
  }

  function setMinter(address _minter) external onlyOwner {
    minter = _minter;
  }

  function mint(address _to, uint256 _amount) external onlyMinter canMint  returns (bool) {
    require(balances[_to] + _amount > balances[_to]); // Guard against overflow
    require(totalSupply + _amount > totalSupply);     // Guard against overflow  (this should never happen)
    totalSupply = totalSupply.add(_amount);
    balances[_to] = balances[_to].add(_amount);
    Mint(_to, _amount);
    return true;
  }

  function finishMinting() external onlyMinter returns (bool) {
    mintingFinished = true;
    MintingFinished();
    return true;
  }


  //=====================================================================================
  // Burning:
  //=====================================================================================


  modifier onlyDestroyer() {
     require(msg.sender == destroyer);
     _;
  }

  function setDestroyer(address _destroyer) external onlyOwner {
    destroyer = _destroyer;
  }

  function setBurnTracker(address _burnTracker) external onlyOwner {
    burnTracker = _burnTracker;
  }

  function burn(uint256 _amount) external onlyDestroyer {
    require(balances[destroyer] >= _amount && _amount > 0);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify external burn tracker before state updates
    if (burnTracker != address(0)) {
        IBurnTracker(burnTracker).onBurn(destroyer, _amount);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[destroyer] = balances[destroyer].sub(_amount);
    totalSupply = totalSupply.sub(_amount);
    Burn(_amount);
  }
}
