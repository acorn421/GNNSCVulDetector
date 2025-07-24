/*
 * ===== SmartInject Injection Details =====
 * Function      : makeCoin
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based minting restrictions. The vulnerability relies on block.timestamp for critical timing logic without proper validation, making it susceptible to timestamp manipulation attacks across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables:**
 *    - `lastMintTime` mapping to track when each address last minted coins
 *    - `MINT_COOLDOWN` constant defining the required waiting period between mints
 *    - `MAX_MINT_PER_PERIOD` constant limiting mint amount per period
 * 
 * 2. **Introduced Timestamp-Dependent Logic:**
 *    - Added cooldown check using `block.timestamp >= lastMintTime[owner] + MINT_COOLDOWN`
 *    - Store current `block.timestamp` in `lastMintTime[owner]` after successful minting
 *    - Time-based access control that persists across transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Owner calls `makeCoin(500000)` at block timestamp 1000
 * - `lastMintTime[owner]` is set to 1000
 * - Tokens are minted successfully
 * - Next mint is blocked until timestamp 1000 + 86400 = 87400
 * 
 * **Transaction 2+ (Exploitation):**
 * - Miner manipulates block.timestamp to be exactly 87400 (or slightly above)
 * - Owner calls `makeCoin(1000000)` in the manipulated block
 * - The cooldown check passes due to timestamp manipulation
 * - `lastMintTime[owner]` is updated to the manipulated timestamp
 * - More tokens are minted bypassing the intended time restriction
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Miner continues manipulating subsequent block timestamps
 * - Owner can mint again sooner than intended by exploiting timestamp drift
 * - Accumulated state changes enable repeated exploitation
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence:** The `lastMintTime` mapping maintains state between transactions, creating a dependency chain
 * 2. **Temporal Dependency:** The vulnerability requires a sequence of transactions over time to exploit the timestamp manipulation
 * 3. **Accumulated Effect:** Each successful exploitation updates the stored timestamp, affecting future minting attempts
 * 4. **Cannot be Atomic:** The exploit requires mining multiple blocks with manipulated timestamps, which cannot occur in a single transaction
 * 
 * **Real-World Impact:**
 * - Miners can collaborate with token owners to bypass minting restrictions
 * - Inflation controls can be circumvented through timestamp manipulation
 * - The 15-second timestamp tolerance in Ethereum makes this practically exploitable
 * - Accumulated over multiple transactions, significant unauthorized minting becomes possible
 */
pragma solidity ^0.4.23;

contract USDT {
    mapping (address => uint256) private balances;
    mapping (address => uint256[2]) private lockedBalances;
    string public name = "USDT";                   //fancy name: eg Simon Bucks
    uint8 public decimals = 6;                //How many decimals to show.
    string public symbol = "USDT";                 //An identifier: eg SBX
    uint256 public totalSupply = 1000000000000000;
    address public owner;
        event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol,
        address _owner
    ) public {
        balances[_owner] = _initialAmount;                   // Give the owner all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
        owner = _owner;                                      // set owner
        
    }
    /*DirectDrop and AirDrop*/
    /*Checking lock limit and time limit while transfering.*/
    function transfer(address _to, uint256 _value) public returns (bool success) {
        //Before ICO finish, only own could transfer.
        if(_to != address(0)){
            if(lockedBalances[msg.sender][1] >= now) {
                require((balances[msg.sender] > lockedBalances[msg.sender][0]) &&
                 (balances[msg.sender] - lockedBalances[msg.sender][0] >= _value));
            } else {
                require(balances[msg.sender] >= _value);
            }
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
    }
    /*With permission, destory token from an address and minus total amount.*/
    function burnFrom(address _who,uint256 _value)public returns (bool){
        require(msg.sender == owner);
        assert(balances[_who] >= _value);
        totalSupply -= _value;
        balances[_who] -= _value;
        lockedBalances[_who][0] = 0;
        lockedBalances[_who][1] = 0;
        return true;
    }
    /*With permission, creating coin.*/
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) private lastMintTime;
    uint256 private constant MINT_COOLDOWN = 1 days;
    uint256 private constant MAX_MINT_PER_PERIOD = 1000000;
    
    function makeCoin(uint256 _value)public returns (bool){
        require(msg.sender == owner);
        
        // Check if cooldown period has passed
        if (lastMintTime[owner] != 0) {
            require(block.timestamp >= lastMintTime[owner] + MINT_COOLDOWN, "Cooldown period not met");
        }
        
        // Additional check: limit minting amount per period
        require(_value <= MAX_MINT_PER_PERIOD, "Exceeds maximum mint per period");
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        totalSupply += _value;
        balances[owner] += _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update last mint time using block.timestamp
        lastMintTime[owner] = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return true;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
    /*With permission, withdraw ETH to owner address from smart contract.*/
    function withdraw() public{
        require(msg.sender == owner);
        msg.sender.transfer(address(this).balance);
    }
    /*With permission, withdraw ETH to an address from smart contract.*/
    function withdrawTo(address _to) public{
        require(msg.sender == owner);
        address(_to).transfer(address(this).balance);
    }
}