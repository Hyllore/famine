/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/25 18:17:28 by amaindro          #+#    #+#             */
/*   Updated: 2015/11/26 15:52:38 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *s1, const char *s2, size_t n)
{
	size_t		i;
	size_t		j;

	i = 0;
	j = 0;
	if (s2[i] == '\0')
		return ((char*)s1);
	while (s1[i] != '\0' && i + j <= n)
	{
		if (s2[j] == '\0')
			return ((char*)&s1[i]);
		if (s1[i + j] == s2[j])
			j++;
		else
		{
			j = 0;
			i++;
		}
	}
	return (0);
}
