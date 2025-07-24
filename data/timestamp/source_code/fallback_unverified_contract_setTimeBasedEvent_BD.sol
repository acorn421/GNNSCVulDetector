/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimeBasedEvent
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability creates a timestamp dependence issue that is stateful and requires multiple transactions to exploit. The vulnerability allows miners to manipulate timestamps to either extend or reduce event duration, affecting bonus distribution. The state persists across transactions through eventStartTime, eventActive, and hasClaimedEventBonus mappings. Exploitation requires: 1) Owner setting an event (transaction 1), 2) Players claiming bonuses during manipulated timeframes (transaction 2+), 3) Event ending with timestamp manipulation (final transaction). The vulnerability is multi-transaction because it requires the event to be set, players to participate, and the timing to be manipulated across multiple blocks.
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
    
    event attackhappened (address attacker, address defender);
    event buyhappened (address buyer, uint countryID);

    function Risk() 
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
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
uint256 public eventStartTime;
uint256 public eventDuration = 3600; // 1 hour default
bool public eventActive = false;
mapping(address => bool) public hasClaimedEventBonus;
uint256 public eventBonusPool = 0;

function setTimeBasedEvent(uint256 _duration) payable returns(bool)
{
    assert(msg.sender == owner);
    assert(msg.value >= 1 finney);
    
    eventStartTime = now;
    eventDuration = _duration;
    eventActive = true;
    eventBonusPool += msg.value;
    
    // Reset claim status for all players
    for(uint256 i = 0; i < playerList.length; i++) {
        hasClaimedEventBonus[playerList[i]] = false;
    }
    
    return true;
}

function claimEventBonus() returns(bool)
{
    assert(eventActive);
    assert(now >= eventStartTime);
    assert(now <= eventStartTime + eventDuration);
    assert(playerCountries[msg.sender].length > 0);
    assert(!hasClaimedEventBonus[msg.sender]);
    
    hasClaimedEventBonus[msg.sender] = true;
    uint256 bonus = eventBonusPool / playerList.length;
    
    if(bonus > 0) {
        msg.sender.transfer(bonus);
    }
    
    return true;
}

function endTimeBasedEvent() returns(bool)
{
    assert(eventActive);
    assert(now > eventStartTime + eventDuration);
    
    eventActive = false;
    // Owner claims remaining bonus pool
    if(eventBonusPool > 0) {
        owner.transfer(eventBonusPool);
        eventBonusPool = 0;
    }
    
    return true;
}
    // === END FALLBACK INJECTION ===

}