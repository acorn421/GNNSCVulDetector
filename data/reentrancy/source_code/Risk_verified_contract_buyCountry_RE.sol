/*
 * ===== SmartInject Injection Details =====
 * Function      : buyCountry
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the buyer about purchase confirmation before state updates. The vulnerability requires a pendingPurchases mapping to track intermediate state and creates a reentrancy window where:
 * 
 * 1. **Transaction 1**: Attacker calls buyCountry, gets callback, calls buyCountry again in callback (country still appears unowned)
 * 2. **Transaction 2**: Attacker exploits accumulated inconsistent state where multiple pending purchases exist
 * 3. **Transaction 3**: Further exploitation of the corrupted ownership state
 * 
 * The vulnerability is stateful because:
 * - pendingPurchases mapping persists between transactions
 * - The contract's state becomes inconsistent after reentrancy
 * - Subsequent transactions can exploit this accumulated inconsistent state
 * 
 * The external call violates the Checks-Effects-Interactions pattern by performing state updates after the external call, allowing attackers to re-enter the function while the contract is in an inconsistent state. This enables multiple purchases of the same country or exploitation of the corrupted game state in later transactions.
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

    // DECLARATION ADDED: Fix for undeclared identifier
    mapping(address => uint8[]) pendingPurchases;

    event attackhappened (address attacker, address defender);
    event buyhappened (address buyer, uint countryID);

    constructor() 
    {
        owner = msg.sender;
    }
    
    function buyCountry(uint8 countryID) payable returns(bool)
    {
        assert(ownerofCountry[countryID]==0); //country unowned
        assert(msg.value == 10 finney); //0.01 ether
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add purchase to pending list before external call
        pendingPurchases[msg.sender].push(countryID);
        
        // External call to notify buyer about purchase confirmation
        // This creates a reentrancy window before state updates
        if(msg.sender.call.value(0)(bytes4(keccak256("onPurchaseConfirmation(uint8)")), countryID)) {
            // Callback successful - proceed with purchase
        }
        
        // State updates happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalmoney +=msg.value;
        playerCountries[msg.sender].push(countryID);
        ownerofCountry[countryID]=msg.sender;
        playerList.push(msg.sender);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Remove from pending after successful purchase
        for(uint i = 0; i < pendingPurchases[msg.sender].length; i++) {
            if(pendingPurchases[msg.sender][i] == countryID) {
                pendingPurchases[msg.sender][i] = pendingPurchases[msg.sender][pendingPurchases[msg.sender].length - 1];
                pendingPurchases[msg.sender].length--;
                break;
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    
}
