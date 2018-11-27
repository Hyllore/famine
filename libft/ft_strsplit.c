/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/27 19:05:22 by amaindro          #+#    #+#             */
/*   Updated: 2018/04/24 14:33:00 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static int			ft_countword(const char *s, char c)
{
	int		nwords;
	int		i;

	i = 0;
	nwords = 0;
	while (s[i] != '\0')
	{
		while (s[i] == c)
			i++;
		if (s[i] != c && s[i] != '\0')
			nwords++;
		while (s[i] != c && s[i] != '\0')
			i++;
	}
	return (nwords);
}

static unsigned int	start(const char *s, char c, int n)
{
	int		i;
	int		k;
	int		j;

	i = 0;
	k = 0;
	j = 0;
	while (k <= n)
	{
		i = i + j;
		j = 0;
		while (s[i] == c)
			i++;
		k++;
		while (s[i + j] != c && s[i + j] != '\0')
			j++;
	}
	return (i);
}

static size_t		ft_len(const char *s, char c, unsigned int i)
{
	size_t	j;

	j = 0;
	while (s[i + j] != c && s[i + j] != '\0')
		j++;
	return (j);
}

char				**ft_strsplit(const char *s, char c)
{
	int		i;
	char	**tab;

	i = 0;
	tab = (char**)malloc(sizeof(char*) * (ft_countword(s, c) + 1));
	if (!tab)
		return (0);
	while (i < ft_countword(s, c))
	{
		tab[i] = ft_strsub(s, start(s, c, i), ft_len(s, c, start(s, c, i)));
		if (!tab[i])
		{
			while (i >= 0)
				free(tab[i--]);
			free(tab);
			return (0);
		}
		i++;
	}
	tab[i] = 0;
	return (tab);
}
