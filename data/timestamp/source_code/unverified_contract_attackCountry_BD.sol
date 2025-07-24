/*
 * ===== SmartInject Injection Details =====
 * Function      : attackCountry
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added timestamp-based attack timing system**: The function now stores `lastAttackTimestamp[attacker]` and calculates time-based bonuses based on the interval between attacks. This creates a stateful vulnerability where the timing of previous attacks affects future battle outcomes.
 * 
 * 2. **Implemented time window bonuses**: Attackers receive strength bonuses (+1, +2, or +3) if they time their attacks within specific windows (1-2 minutes, 5-10 minutes, or 30-60 minutes since their last attack). This creates predictable timing patterns that can be exploited.
 * 
 * 3. **Modified randomness generation**: The battle outcome randomness now incorporates `block.timestamp` using `keccak256(block.blockhash(block.number-1), attackTimestamp)`, making the randomness dependent on when the transaction is mined.
 * 
 * **Multi-Transaction Exploitation**:
 * - **Transaction 1**: Attacker performs initial attack to establish baseline timestamp in `lastAttackTimestamp[attacker]`
 * - **Transaction 2+**: Attacker times subsequent attacks to fall within bonus windows, gaining unfair advantages
 * 
 * **Stateful Nature**: The vulnerability requires persistent state (`lastAttackTimestamp` mapping) that accumulates across multiple transactions, making it impossible to exploit in a single transaction.
 * 
 * **Realistic Exploitation**: Miners can manipulate block timestamps within the ~900 second tolerance to ensure attacks fall within bonus windows, and sophisticated attackers can coordinate multiple transactions to maximize timing bonuses over time.
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

    // --- FIX: Added declaration for lastAttackTimestamp mapping ---
    mapping(address => uint256) lastAttackTimestamp;
    
    event attackhappened (address attacker, address defender);
    event buyhappened (address buyer, uint countryID);

    // FIX: Use constructor!
    constructor() 
    {
        owner = msg.sender;
    }
    
    function buyCountry(uint8 countryID) payable returns(bool)
    {
        assert(ownerofCountry[countryID]==0); //country unowned
        assert(msg.value == 10 finney); //0.01 ether
        
        totalmoney +=msg.value;
        playerCountries[msg.sender].push(countryID);
        ownerofCountry[countryID]=msg.sender;
        playerList.push(msg.sender);
        
        buyhappened(msg.sender,countryID);
        
        return true;
    }
    
    function attackCountry(uint8 countryID)
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

        for(uint256 i=14;i>=11;i--)
            winnerloser[i]=winnerloser[i-1];
        for(i=9;i>=6;i--)
            winnerloser[i]=winnerloser[i-1];
        for(i=4;i>=1;i--)
            winnerloser[i]=winnerloser[i-1];
        
        uint256 loopcount=0;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store attack timestamp for battle outcome calculation
        uint256 attackTimestamp = block.timestamp;
        
        // Calculate time-based attack bonus using stored timestamp from previous attack
        uint256 timeSinceLastAttack = attackTimestamp - lastAttackTimestamp[attacker];
        uint256 timeBonus = 0;
        
        // Attackers get bonus if they time their attacks within specific windows
        if(timeSinceLastAttack >= 60 && timeSinceLastAttack < 120) {
            timeBonus = 1; // 1-2 minute window gives +1 bonus
        } else if(timeSinceLastAttack >= 300 && timeSinceLastAttack < 600) {
            timeBonus = 2; // 5-10 minute window gives +2 bonus
        } else if(timeSinceLastAttack >= 1800 && timeSinceLastAttack < 3600) {
            timeBonus = 3; // 30-60 minute window gives +3 bonus
        }
        
        // Update stored timestamp for future attacks
        lastAttackTimestamp[attacker] = attackTimestamp;
        
        // Apply time bonus to attacker strength
        a += timeBonus;
        if(a > 10) a = 10; // Cap at maximum strength
        
        // Use timestamp-influenced randomness for battle outcome
        lastR = uint256(keccak256(block.blockhash(block.number-1), attackTimestamp)) % (a + b);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    function isGameEnd()
    {
        uint256 loopcount=playerList.length;
        address winner=owner;
        
        //require 15 country ownership for testing
        bool del=false;
        for (uint8 i=0; i<loopcount;i++)
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
                ownerofCountry[i]=0;
            }
            playerList.length=0;
            for(i=0;i<10;i++)
                winnerloser[i]=address(0);
        }
    }
    function setwinnerLimit (uint8 x)
    {
        assert(msg.sender==owner);
        winnerLimit=x;
    }
    function getCountryOwnershipList() constant returns (address[178])
    {
        return ownerofCountry;
    }
    function getTotalBet()constant returns (uint256)
    {
        return totalmoney;
    }
    function getaddr(address ax, uint8 bx) constant returns(address)
    {
        return playerCountries[ax][bx];
    }
    function len(address ax) constant returns(uint)
    {
        return playerCountries[ax].length;
    }
    function lastrandom() constant returns(uint256)
    {
        return lastR;
    }
    function getwinnerloser() constant returns(address[15])
    {
        return winnerloser;
    }
    function lastgamewinner() constant returns(address)
    {
        return lastgameendWinner;
    }
    
}
