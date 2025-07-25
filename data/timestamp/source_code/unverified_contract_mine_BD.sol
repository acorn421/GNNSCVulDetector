/*
 * ===== SmartInject Injection Details =====
 * Function      : mine
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
 * Introduced a timestamp-dependent mining rate limit system that creates a multi-transaction vulnerability. The function now uses block.timestamp to create hourly mining windows and tracks cumulative mining amounts per window using state variables. The vulnerability allows miners to manipulate timestamps to bypass rate limits across multiple transactions.
 * 
 * **State Variables Required (would be added to contract):**
 * - `uint256 public lastMiningWindow` - tracks the last mining window
 * - `uint256 public miningAmountThisWindow` - tracks cumulative mining in current window
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Mine maximum allowed tokens in current hour window
 * 2. **Timestamp manipulation**: Miner influences block.timestamp to advance to next hour window
 * 3. **Transaction 2**: Mine again immediately, bypassing the intended 1-hour cooldown
 * 4. **Repeat**: Continue this pattern to mine far more tokens than intended rate limits allow
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on accumulated state (`miningAmountThisWindow`) that persists between transactions
 * - Exploitation requires multiple mining operations across different timestamp windows
 * - Single transaction cannot demonstrate the rate limit bypass - need sequential transactions with timestamp manipulation
 * - The state variable `lastMiningWindow` must be updated in one transaction and then exploited in subsequent transactions
 * 
 * **Realistic Attack Scenario:**
 * - Miners could coordinate to influence block timestamps slightly
 * - Sequential mining transactions could exploit the timestamp-dependent window calculations
 * - Over time, this allows circumventing intended mining rate limits and potentially mining excessive tokens
 */
// 0.4.20+commit.3155dd80.Emscripten.clang
pragma solidity ^0.4.20;

// Ethereum Token callback
interface tokenRecipient {
  function receiveApproval( address from, uint256 value, bytes data ) external;
}

// ERC223 callback
interface ContractReceiver {
  function tokenFallback( address from, uint value, bytes data ) external;
}

contract owned {
  address public owner;

  constructor() public {
    owner = msg.sender;
  }

  function changeOwner( address _miner ) public onlyOwner {
    owner = _miner;
  }

  modifier onlyOwner {
    require (msg.sender == owner);
    _;
  }
}

// ERC20 token with added ERC223 and Ethereum-Token support
//
// Blend of multiple interfaces:
// - https://theethereum.wiki/w/index.php/ERC20_Token_Standard
// - https://www.ethereum.org/token (uncontrolled, non-standard)
// - https://github.com/Dexaran/ERC23-tokens/blob/Recommended/ERC223_Token.sol

contract MineableToken is owned {

  string  public name;
  string  public symbol;
  uint8   public decimals;
  uint256 public totalSupply;
  uint256 public supplyCap;

  mapping( address => uint256 ) balances_;
  mapping( address => mapping(address => uint256) ) allowances_;

  // Added variables for mining rate limiting
  uint256 public lastMiningWindow;
  uint256 public miningAmountThisWindow;

  // ERC20
  event Approval( address indexed owner,
                  address indexed spender,
                  uint value );

  // ERC20-compatible version only, breaks ERC223 compliance but block
  // explorers and exchanges expect ERC20. Also, cannot overload events

  event Transfer( address indexed from,
                  address indexed to,
                  uint256 value );
                  //bytes    data );

  // Ethereum Token
  event Burn( address indexed from,
              uint256 value );

  constructor() public {
    decimals = uint8(18);
    supplyCap = 4 * 1e9 * 10**uint256(decimals);
    name = "Jbox";
    symbol = "JBX";
  }

  function mine( uint256 qty ) public onlyOwner {

    require (    (totalSupply + qty) > totalSupply
              && (totalSupply + qty) <= supplyCap
            );

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Mining rate limit based on timestamp - creates timestamp dependence vulnerability
    uint256 currentMiningWindow = block.timestamp / 3600; // 1 hour windows
    uint256 maxMiningPerWindow = supplyCap / 1000; // 0.1% of supply cap per hour
    
    // Track mining amount per time window
    if (lastMiningWindow != currentMiningWindow) {
        // Reset mining amount for new window
        miningAmountThisWindow = 0;
        lastMiningWindow = currentMiningWindow;
    }
    
    // Check if mining amount exceeds window limit
    require(miningAmountThisWindow + qty <= maxMiningPerWindow);
    
    // Update mining tracking
    miningAmountThisWindow += qty;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    totalSupply += qty;
    balances_[owner] += qty;
    Transfer( address(0), owner, qty );
  }

  function cap() public constant returns(uint256) {
    return supplyCap;
  }

  // ERC20
  function balanceOf( address owner ) public constant returns (uint) {
    return balances_[owner];
  }

  // ERC20
  function approve( address spender, uint256 value ) public
  returns (bool success)
  {
    // WARNING! When changing the approval amount, first set it back to zero
    // AND wait until the transaction is mined. Only afterwards set the new
    // amount. Otherwise you may be prone to a race condition attack.
    // See: https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729

    allowances_[msg.sender][spender] = value;
    Approval( msg.sender, spender, value );
    return true;
  }
 
  // recommended fix for known attack on any ERC20
  function safeApprove( address _spender,
                        uint256 _currentValue,
                        uint256 _value ) public
  returns (bool success)
  {
    // If current allowance for _spender is equal to _currentValue, then
    // overwrite it with _value and return true, otherwise return false.

    if (allowances_[msg.sender][_spender] == _currentValue)
      return approve(_spender, _value);

    return false;
  }

  // ERC20
  function allowance( address owner, address spender ) public constant
  returns (uint256 remaining)
  {
    return allowances_[owner][spender];
  }

  // ERC20
  function transfer(address to, uint256 value) public
  returns (bool success)
  {
    bytes memory empty; // null
    _transfer( msg.sender, to, value, empty );
    return true;
  }

  // ERC20
  function transferFrom( address from, address to, uint256 value ) public
  returns (bool success)
  {
    require( value <= allowances_[from][msg.sender] );

    allowances_[from][msg.sender] -= value;
    bytes memory empty;
    _transfer( from, to, value, empty );

    return true;
  }

  // Ethereum Token
  function approveAndCall( address spender,
                           uint256 value,
                           bytes context ) public
  returns (bool success)
  {
    if ( approve(spender, value) )
    {
      tokenRecipient recip = tokenRecipient( spender );

      if (isContract(recip))
        recip.receiveApproval( msg.sender, value, context );

      return true;
    }

    return false;
  }        

  // Ethereum Token
  function burn( uint256 value ) public
  returns (bool success)
  {
    require( balances_[msg.sender] >= value );
    balances_[msg.sender] -= value;
    totalSupply -= value;

    Burn( msg.sender, value );
    return true;
  }

  // Ethereum Token
  function burnFrom( address from, uint256 value ) public
  returns (bool success)
  {
    require( balances_[from] >= value );
    require( value <= allowances_[from][msg.sender] );

    balances_[from] -= value;
    allowances_[from][msg.sender] -= value;
    totalSupply -= value;

    Burn( from, value );
    return true;
  }

  // ERC223 Transfer and invoke specified callback
  function transfer( address to,
                     uint value,
                     bytes data,
                     string custom_fallback ) public returns (bool success)
  {
    _transfer( msg.sender, to, value, data );

    // throws if custom_fallback is not a valid contract call
    require( address(to).call.value(0)(bytes4(keccak256(custom_fallback)),
             msg.sender,
             value,
             data) );

    return true;
  }

  // ERC223 Transfer to a contract or externally-owned account
  function transfer( address to, uint value, bytes data ) public
  returns (bool success)
  {
    if (isContract(to)) {
      return transferToContract( to, value, data );
    }

    _transfer( msg.sender, to, value, data );
    return true;
  }

  // ERC223 Transfer to contract and invoke tokenFallback() method
  function transferToContract( address to, uint value, bytes data ) private
  returns (bool success)
  {
    _transfer( msg.sender, to, value, data );

    ContractReceiver rx = ContractReceiver(to);

    if (isContract(rx)) {
      rx.tokenFallback( msg.sender, value, data );
      return true;
    }

    return false;
  }

  // ERC223 fetch contract size (must be nonzero to be a contract)
  function isContract( address _addr ) private constant returns (bool)
  {
    uint length;
    assembly { length := extcodesize(_addr) }
    return (length > 0);
  }

  function _transfer( address from,
                      address to,
                      uint value,
                      bytes data ) internal
  {
    require( to != 0x0 );
    require( balances_[from] >= value );
    require( balances_[to] + value > balances_[to] ); // catch overflow

    balances_[from] -= value;
    balances_[to] += value;

    bytes memory ignore;
    ignore = data;                    // ignore compiler warning
    Transfer( from, to, value ); // ERC20-version, ignore data
  }
}
