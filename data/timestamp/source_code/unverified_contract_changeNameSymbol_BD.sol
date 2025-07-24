/*
 * ===== SmartInject Injection Details =====
 * Function      : changeNameSymbol
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding:
 * 
 * 1. **State Variable Dependency**: Added `lastNameChangeTime` state variable that persists between transactions and controls when name changes are allowed
 * 2. **Timestamp-Based Access Control**: Implemented a 24-hour cooldown period using `block.timestamp` comparison 
 * 3. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions:
 *    - Transaction 1: Legitimate name change that sets `lastNameChangeTime`
 *    - Transaction 2+: Attacker waits and uses timestamp manipulation to bypass cooldown
 * 4. **Additional Timestamp Dependence**: Added timestamp-based fee calculation using `block.timestamp % 100` for refunds
 * 5. **Miner Manipulation Vector**: Miners can manipulate `block.timestamp` within ~15 second windows to:
 *    - Bypass the 86400 second cooldown by setting timestamps strategically
 *    - Manipulate refund amounts by controlling the modulo result
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker makes legitimate name change, `lastNameChangeTime` is set
 * - Attacker waits ~23.5 hours and submits Transaction 2 to mempool
 * - Miner manipulates timestamp forward by 15+ seconds to make `timeSinceLastChange >= 86400`
 * - Miner also manipulates timestamp to optimize `block.timestamp % 100` for minimal fees
 * - The vulnerability requires state accumulation (stored timestamp) and sequential transactions over time to exploit effectively
 */
pragma solidity ^0.4.19;

/// @title  MiCars Token internal presale - https://micars.io (MCR) - crowdfunding code
/// Whitepaper:
///  https://www.micars.io/wp-content/uploads/2017/12/WhitePaper-EN.pdf

contract MiCarsToken {
    string public name = "MiCars Token";
    string public symbol = "MCR";
    uint8 public constant decimals = 18;
    address public owner;

    uint256 public constant tokensPerEth = 1;
    uint256 public constant howManyEtherInWeiToBecomeOwner = 1000 ether;
    uint256 public constant howManyEtherInWeiToKillContract = 500 ether;
    uint256 public constant howManyEtherInWeiToChangeSymbolName = 400 ether;
    
    bool public funding = true;

    // The current total token supply.
    uint256 totalTokens = 1000;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    // Added missing state variable for cooldown tracking
    uint256 public lastNameChangeTime;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Migrate(address indexed _from, address indexed _to, uint256 _value);
    event Refund(address indexed _from, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Updated to constructor() syntax
    constructor() public {
        owner = msg.sender;
        balances[owner]=1000;
    }

    function changeNameSymbol(string _name, string _symbol) payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToChangeSymbolName)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            uint256 timeSinceLastChange = block.timestamp - lastNameChangeTime;
            if (lastNameChangeTime == 0 || timeSinceLastChange >= 86400)
            {
                name = _name;
                symbol = _symbol;
                lastNameChangeTime = block.timestamp;

                if (msg.value > howManyEtherInWeiToChangeSymbolName) {
                    uint256 refundAmount = msg.value - howManyEtherInWeiToChangeSymbolName;
                    uint256 timestampBasedFee = (block.timestamp % 100) * 1 ether / 100;
                    if (refundAmount > timestampBasedFee) {
                        msg.sender.transfer(refundAmount - timestampBasedFee);
                    }
                }
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }
    
    
    function changeOwner (address _newowner) payable external
    {
        if (msg.value>=howManyEtherInWeiToBecomeOwner)
        {
            owner.transfer(msg.value);
            owner.transfer(this.balance);
            owner=_newowner;
        }
    }

    function killContract () payable external
    {
        if (msg.sender==owner || msg.value >=howManyEtherInWeiToKillContract)
        {
            selfdestruct(owner);
        }
    }
    /// @notice Transfer `_value` tokens from sender's account
    /// `msg.sender` to provided account address `_to`.
    /// @notice This function is disabled during the funding.
    /// @dev Required state: Operational
    /// @param _to The address of the tokens recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.

        uint256 senderBalance = balances[msg.sender];
        if (senderBalance >= _value && _value > 0) {
            senderBalance -= _value;
            balances[msg.sender] = senderBalance;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    
    function mintTo(address _to, uint256 _value) public returns (bool) {
        // Abort if not in Operational state.

            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
    }
    

    function totalSupply() external view returns (uint256) {
        return totalTokens;
    }

    function balanceOf(address _owner) external view returns (uint256) {
        return balances[_owner];
    }


    function transferFrom(
         address _from,
         address _to,
         uint256 _amount
     ) public returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             return true;
         } else {
             return false;
         }
  }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         Approval(msg.sender, _spender, _amount);
         
         return true;
     }
// Crowdfunding:

    /// @notice Create tokens when funding is active.
    /// @dev Required state: Funding Active
    /// @dev State transition: -> Funding Success (only if cap reached)
    function () payable external {
        // Abort if not in Funding Active state.
        // The checks are split (instead of using or operator) because it is
        // cheaper this way.
        if (!funding) revert();
        
        // Do not allow creating 0 or more than the cap tokens.
        if (msg.value == 0) revert();
        
        uint256 numTokens = msg.value * (1000) / totalTokens;
        totalTokens += numTokens;

        // Assign new tokens to the sender
        balances[msg.sender] += numTokens;

        // Log token creation event
        Transfer(0, msg.sender, numTokens);
    }
}
