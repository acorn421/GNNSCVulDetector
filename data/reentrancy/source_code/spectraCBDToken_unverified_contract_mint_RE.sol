/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `_to` using `_to.call(abi.encodeWithSignature("beforeMint(uint256)", _amount))` before state updates
 * - Added a check `if (_to.code.length > 0)` to only call contracts, making the attack surface realistic
 * - The external call occurs BEFORE the critical state updates (`totalSupply` and `balances[_to]`)
 * - Used low-level `call` instead of requiring interface, making it more realistic for notification systems
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract implementing `beforeMint(uint256)`
 * - Attacker calls `mint(maliciousContract, 1000)` 
 * - During the `beforeMint` callback, the malicious contract reads current state (`balances[maliciousContract]` = 0, `totalSupply` = X)
 * - The malicious contract stores this state information for later use
 * - After callback returns, the mint function updates state (`balances[maliciousContract]` = 1000, `totalSupply` = X+1000)
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `mint(maliciousContract, 2000)`
 * - During the `beforeMint` callback, the malicious contract:
 *   - Reads current state (`balances[maliciousContract]` = 1000 from previous transaction)
 *   - Compares with stored state from Transaction 1
 *   - Can now exploit the time window where external call happens before state updates
 *   - Could potentially call other functions that depend on the current balance/supply state
 *   - The malicious contract could trigger complex multi-step attacks based on accumulated state
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Repeated calls accumulate state changes, each providing the attacker with more information and bigger balance inconsistencies
 * - The attack becomes more profitable with each subsequent mint operation
 * - The attacker can use the accumulated state across multiple transactions to manipulate other contract functions
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Accumulation Dependency:**
 * - The vulnerability exploits the accumulated balance state from previous mint transactions
 * - Each transaction builds upon the state created by previous transactions
 * - The attack's effectiveness increases with the number of accumulated mint operations
 * 
 * **Cross-Transaction State Inconsistency:**
 * - The external call in Transaction N can read state that was established in Transaction N-1
 * - The attacker needs multiple transactions to build up meaningful balances to exploit
 * - The time window between external call and state update becomes more valuable as balances grow
 * 
 * **Multi-Step Attack Coordination:**
 * - First transaction establishes the attack contract as a valid recipient
 * - Subsequent transactions allow the attacker to build up balances and exploit the reentrancy window
 * - The attack requires coordination across multiple blocks/transactions to be effective
 * 
 * **Economic Incentive Growth:**
 * - Single transaction reentrancy would only affect small amounts
 * - Multiple transactions allow the attacker to build up significant token balances
 * - The economic incentive to exploit grows with each accumulated mint operation
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to be effectively exploited, while maintaining the original function's intended behavior.
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

// This is an ERC-20 token contract based on Open Zepplin's StandardToken
// and MintableToken plus the ability to burn tokens.
//
// Token can be burned by a special 'destroyer' role that can only
// burn its tokens.
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
  function approve(address _spender, uint256 _value) public whenMintingFinished returns (bool) {
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

  /**
   * approve should be called when allowed[_spender] == 0. To increment
   * allowed value is better to use this function to avoid 2 calls (and wait until
   * the first transaction is mined)
   * From MonolithDAO Token.sol
   */
  function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
    allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
    emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

  function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
    uint oldValue = allowed[msg.sender][_spender];
    if (_subtractedValue > oldValue) {
      allowed[msg.sender][_spender] = 0;
    } else {
      allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
    }
    emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }


  //=====================================================================================
  // Minting:
  //=====================================================================================

  bool public mintingFinished = false;
  address public destroyer;
  address public minter;

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify the recipient before updating state - VULNERABLE to reentrancy
    if (isContract(_to)) {
        // Call to potentially malicious contract before state updates
        (bool success, ) = _to.call(abi.encodeWithSignature("beforeMint(uint256)", _amount));
        // Continue regardless of success to maintain functionality
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    totalSupply = totalSupply.add(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Mint(_to, _amount);
    return true;
  }

  function finishMinting() external onlyMinter returns (bool) {
    mintingFinished = true;
    emit MintingFinished();
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

  function burn(uint256 _amount) external onlyDestroyer {
    require(balances[destroyer] >= _amount && _amount > 0);
    balances[destroyer] = balances[destroyer].sub(_amount);
    totalSupply = totalSupply.sub(_amount);
    emit Burn(_amount);
  }

  // Helper function to check if address is a contract (since address.code does not exist in 0.4.x)
  function isContract(address _addr) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(_addr) }
    return size > 0;
  }
}
