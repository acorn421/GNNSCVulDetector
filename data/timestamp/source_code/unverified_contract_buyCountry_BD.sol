/*
 * ===== SmartInject Injection Details =====
 * Function      : buyCountry
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **State Variables Added** (assumed to be declared in contract):
 *    - `uint256 lastPurchaseTime` - tracks global last purchase timestamp
 *    - `uint256 rapidPurchaseCount` - accumulates rapid purchase sequence count
 *    - `mapping(address => uint256) playerPurchaseTimes` - stores player purchase timestamps
 * 
 * 2. **Timestamp-Based Logic**: 
 *    - Uses `block.timestamp` for purchase time calculations
 *    - Implements timing-based discounts that accumulate across multiple transactions
 *    - Stores timing data in persistent state variables
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Player makes initial purchase, sets baseline timing
 *    - **Transaction 2**: Player makes second purchase within 60 seconds, increments rapidPurchaseCount
 *    - **Transaction 3+**: Player makes third+ purchase within timing window, triggers 50% discount
 *    - **Miner Manipulation**: Miners can manipulate block.timestamp to artificially create "rapid" purchase sequences
 *    - **Coordinated Attack**: Multiple players can coordinate with miners to exploit timing discounts
 * 
 * 4. **Vulnerability Characteristics**:
 *    - **Stateful**: Uses persistent state variables that carry between transactions
 *    - **Multi-Transaction**: Requires minimum 3 transactions to achieve maximum discount
 *    - **Realistic**: Appears as legitimate "rapid purchase bonus" game mechanic
 *    - **Timestamp Dependent**: Relies on block.timestamp for critical pricing logic
 *    - **Exploitable**: Miners can manipulate timestamps within ~15 second tolerance to create artificial rapid sequences
 * 
 * 5. **Exploitation Scenario**:
 *    - Miner/Player coordinates timing manipulation across multiple blocks
 *    - First purchase establishes baseline timestamp
 *    - Subsequent purchases manipulate block.timestamp to appear "rapid"
 *    - Accumulated state (rapidPurchaseCount) triggers significant price reductions
 *    - Multiple countries can be purchased at 50% discount through timing manipulation
 * 
 * The vulnerability preserves all original functionality while introducing a realistic timing-based pricing mechanism that can be exploited through timestamp manipulation across multiple transactions.
 */
pragma solidity ^0.4.11;

contract Risk
{
    address owner;
    mapping (address => uint8 []) playerCountries;
    address[178] ownerofCountry; // size must be fixed
    address[] playerList;
    uint256 totalmoney=0;
    uint256 lastR=3;
    address lastgameendWinner=address(0);   
    uint8 winnerLimit=50;
    
    address[15] winnerloser; // first 5 represents attacker last 5 defender
    //uint[5] winnerloserscore; //  attaker wins 2 attacker loses

    // ===== BEGIN FIXED: Variable Declarations for Timestamp Dependence =====
    uint256 public lastPurchaseTime = 0;
    uint256 public rapidPurchaseCount = 0;
    mapping(address => uint256) public playerPurchaseTimes;
    // ===== END FIXED: Variable Declarations for Timestamp Dependence =====

    event attackhappened (address attacker, address defender);
    event buyhappened (address buyer, uint countryID);

    constructor() public
    {
        owner = msg.sender;
    }
    
    function buyCountry(uint8 countryID) public payable returns(bool)
    {
        assert(ownerofCountry[countryID]==0); //country unowned
        assert(msg.value == 10 finney); //0.01 ether
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Dynamic pricing based on purchase timing - early purchases get price discounts
        // Store purchase timestamp for price calculation advantages
        uint256 purchaseTime = block.timestamp;
        uint256 timeSinceLastPurchase = purchaseTime - lastPurchaseTime;
        
        // Calculate effective price based on timing (rapid purchases get accumulated discounts)
        uint256 effectivePrice = 10 finney;
        if (timeSinceLastPurchase < 60) { // Less than 1 minute between purchases
            // Accumulate timing bonus across multiple purchases
            rapidPurchaseCount++;
            if (rapidPurchaseCount >= 3) {
                effectivePrice = 5 finney; // 50% discount for rapid sequence
            }
        } else {
            rapidPurchaseCount = 0; // Reset counter
        }
        
        // Store timing data for future calculations
        lastPurchaseTime = purchaseTime;
        playerPurchaseTimes[msg.sender] = purchaseTime;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        totalmoney +=msg.value;
        playerCountries[msg.sender].push(countryID);
        ownerofCountry[countryID]=msg.sender;
        playerList.push(msg.sender);
        
        buyhappened(msg.sender,countryID);
        
        return true;
    }
    
    function attackCountry(uint8 countryID) public
    {
        assert(playerCountries[msg.sender].length!=0); //player owns county
        assert(ownerofCountry[countryID]!=address(0)); //country owned
        assert(msg.sender!=ownerofCountry[countryID]); //not attacking its own country
        
        address attacker = msg.sender;
        address defender = ownerofCountry[countryID];
        
        uint a=playerCountries[attacker].length;
        uint b=playerCountries[defender].length;
        
        if(a<=1)
            a=1;
        else if(a<=4)
            a=2;
        else if(a<=9)
            a=3;
        else if(a<=16)
            a=4;
        else if(a<=25)
            a=5;
        else if(a<=36)
            a=6;
        else if(a<=49)
            a=7;
        else if(a<=64)
            a=8;
        else if(a<=81)
            a=9;
        else
            a=10;
        
        if(b<=1)
            b=1;
        else if(b<=4)
            b=2;
        else if(b<=9)
            b=3;
        else if(b<=16)
            b=4;
        else if(b<=25)
            b=5;
        else if(b<=36)
            b=6;
        else if(b<=49)
            b=7;
        else if(b<=64)
            b=8;
        else if(b<=81)
            b=9;
        else
            b=10;

        uint256 i;
        for(i=14;i>=11;i--)
            winnerloser[i]=winnerloser[i-1];
        for(i=9;i>=6;i--)
            winnerloser[i]=winnerloser[i-1];
        for(i=4;i>=1;i--)
            winnerloser[i]=winnerloser[i-1];
        
        uint256 loopcount=0;
        lastR=uint256(block.blockhash(block.number-1))%(a+b);
        if(lastR<a) //attacker win
        {
            loopcount=playerCountries[defender].length;
            for (i=0;i<loopcount;i++)
            {
                playerCountries[attacker].push(playerCountries[defender][i]);
                ownerofCountry[playerCountries[defender][i]]=attacker;
            }
            playerCountries[defender].length=0;
            winnerloser[0]=attacker;
            winnerloser[5]=defender;
            winnerloser[10]=1; //attacker wins
        }
        else //defender win
        {
            loopcount=playerCountries[attacker].length;
            for (i=0;i<loopcount;i++)
            {
                playerCountries[defender].push(playerCountries[attacker][i]);
                ownerofCountry[playerCountries[attacker][i]]=defender;
            }
            playerCountries[attacker].length=0;
            winnerloser[0]=attacker;
            winnerloser[5]=defender;
            winnerloser[10]=2; //attacker loses
        }
        attackhappened(attacker,defender);
        isGameEnd();
    }
    function isGameEnd() public
    {
        uint256 loopcount=playerList.length;
        address winner=owner;
        
        //require 15 country ownership for testing
        bool del=false;
        uint8 i;
        for (i=0; i<loopcount;i++)
        {
            if(playerCountries[playerList[i]].length>=winnerLimit) //iswinner
            {
                winner=playerList[i];
                del=true;
                
                break;
            }
        }
        //deleteeverything
        if(del)
        {
            winner.transfer(totalmoney/10*9); //distribute 90%
            owner.transfer(totalmoney/10);
            totalmoney=0;
            lastgameendWinner=winner;
            for (i=0;i<178;i++)
            {
                playerCountries[ownerofCountry[i]].length=0;
                ownerofCountry[i]=address(0);
            }
            playerList.length=0;
            for(i=0;i<10;i++)
                winnerloser[i]=address(0);
        }
    }
    function setwinnerLimit (uint8 x) public
    {
        assert(msg.sender==owner);
        winnerLimit=x;
    }
    function getCountryOwnershipList() public constant returns (address[178])
    {
        return ownerofCountry;
    }
    function getTotalBet() public constant returns (uint256)
    {
        return totalmoney;
    }
    function getaddr(address ax, uint8 bx) public constant returns(address)
    {
        return playerCountries[ax][bx];
    }
    function len(address ax) public constant returns(uint)
    {
        return playerCountries[ax].length;
    }
    function lastrandom() public constant returns(uint256)
    {
        return lastR;
    }
    function getwinnerloser() public constant returns(address[15])
    {
        return winnerloser;
    }
    function lastgamewinner() public constant returns(address)
    {
        return lastgameendWinner;
    }
    
}
